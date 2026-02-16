package holepunch

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/host/eventbus"
	ma "github.com/multiformats/go-multiaddr"
)

// STUN constants (RFC 5389)
const (
	stunMagicCookie    = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunAttrMappedAddr = 0x0001
	stunAttrXorMapped  = 0x0020
	stunHeaderSize     = 20
)

type stunMappedAddr struct {
	IP   net.IP
	Port int
}

func buildSTUNBindingRequest() ([]byte, [12]byte) {
	pkt := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(pkt[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	var txID [12]byte
	rand.Read(txID[:])
	copy(pkt[8:20], txID[:])
	return pkt, txID
}

func parseSTUNBindingResponse(data []byte, txID [12]byte) (*stunMappedAddr, error) {
	if len(data) < stunHeaderSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingSuccess {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%04x", msgType)
	}
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}
	for i := 0; i < 12; i++ {
		if data[8+i] != txID[i] {
			return nil, fmt.Errorf("transaction ID mismatch")
		}
	}

	msgLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < stunHeaderSize+int(msgLen) {
		return nil, fmt.Errorf("truncated response")
	}

	var mapped *stunMappedAddr
	pos := stunHeaderSize
	end := stunHeaderSize + int(msgLen)
	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(data[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > end {
			break
		}
		switch attrType {
		case stunAttrXorMapped:
			if m := parseXorMappedAddress(data[pos:pos+attrLen], data[4:8], data[8:20]); m != nil {
				return m, nil
			}
		case stunAttrMappedAddr:
			if mapped == nil {
				mapped = parseMappedAddress(data[pos : pos+attrLen])
			}
		}
		pos += attrLen
		if pad := attrLen % 4; pad != 0 {
			pos += 4 - pad
		}
	}
	if mapped != nil {
		return mapped, nil
	}
	return nil, fmt.Errorf("no mapped address in STUN response")
}

func parseXorMappedAddress(data, magicBytes, txID []byte) *stunMappedAddr {
	if len(data) < 8 {
		return nil
	}
	family := data[1]
	if family != 0x01 { // IPv4 only
		return nil
	}
	xport := binary.BigEndian.Uint16(data[2:4])
	port := xport ^ uint16(binary.BigEndian.Uint32(magicBytes)>>16)

	xip := make([]byte, 4)
	copy(xip, data[4:8])
	magic := binary.BigEndian.Uint32(magicBytes)
	ipVal := binary.BigEndian.Uint32(xip) ^ magic
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)

	return &stunMappedAddr{IP: ip, Port: int(port)}
}

func parseMappedAddress(data []byte) *stunMappedAddr {
	if len(data) < 8 {
		return nil
	}
	if data[1] != 0x01 { // IPv4
		return nil
	}
	port := binary.BigEndian.Uint16(data[2:4])
	ip := net.IP(data[4:8])
	return &stunMappedAddr{IP: ip, Port: int(port)}
}

func stunQuery(conn *net.UDPConn, serverAddr string) (*stunMappedAddr, error) {
	addr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", serverAddr, err)
	}
	pkt, txID := buildSTUNBindingRequest()
	conn.SetWriteDeadline(time.Now().Add(STUNTimeout))
	if _, err := conn.WriteTo(pkt, addr); err != nil {
		return nil, fmt.Errorf("write to %s: %w", serverAddr, err)
	}
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(STUNTimeout))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", serverAddr, err)
	}
	return parseSTUNBindingResponse(buf[:n], txID)
}

// DetectNAT detects the NAT type by querying multiple STUN servers.
func DetectNAT(stunServers []string) (*NATInfo, error) {
	if len(stunServers) < 2 {
		return nil, fmt.Errorf("need at least 2 STUN servers, got %d", len(stunServers))
	}

	sock1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer sock1.Close()

	var results []stunMappedAddr
	var publicIPs []string

	for _, server := range stunServers {
		mapped, err := stunQuery(sock1, server)
		if err != nil {
			log.Debug("STUN query failed", "server", server, "err", err)
			continue
		}
		log.Debug("STUN response", "server", server, "mapped_ip", mapped.IP, "mapped_port", mapped.Port)
		results = append(results, *mapped)
		publicIPs = append(publicIPs, mapped.IP.String())
	}

	if len(results) < 2 {
		if len(results) == 1 {
			return &NATInfo{
				Type:       NATUnknown,
				PublicIP:   results[0].IP.String(),
				PublicPort: results[0].Port,
			}, fmt.Errorf("only got response from 1 STUN server (need 2+)")
		}
		return nil, fmt.Errorf("no STUN responses received")
	}

	uniqueIPs := uniqueStrings(publicIPs)

	allSamePort := true
	basePort := results[0].Port
	for _, r := range results[1:] {
		if r.Port != basePort {
			allSamePort = false
			break
		}
	}

	info := &NATInfo{
		PublicIP:   results[0].IP.String(),
		PublicPort: results[0].Port,
	}

	if allSamePort {
		info.Type = NATCone
		log.Debug("NAT detected", "type", info.Type, "public_ip", info.PublicIP, "public_port", info.PublicPort)
		return info, nil
	}

	// Ports differ → Symmetric NAT
	if len(uniqueIPs) > 1 {
		info.Type = NATSymmetricHard
		log.Debug("NAT detected", "type", info.Type, "reason", "multiple_public_IPs")
		return info, nil
	}

	ports := make([]int, len(results))
	for i, r := range results {
		ports[i] = r.Port
	}
	sort.Ints(ports)

	maxPortDiff := ports[len(ports)-1] - ports[0]
	if maxPortDiff > 100 {
		info.Type = NATSymmetricHard
		log.Debug("NAT detected", "type", info.Type, "port_range", maxPortDiff)
		return info, nil
	}

	// Extra bind test: new socket to same STUN server
	sock2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		info.Type = NATSymmetricHard
		return info, nil
	}
	defer sock2.Close()

	extraMapped, err := stunQuery(sock2, stunServers[0])
	if err != nil {
		info.Type = NATSymmetricHard
		return info, nil
	}

	maxPort := ports[len(ports)-1]
	minPort := ports[0]

	incDiff := extraMapped.Port - maxPort
	decDiff := minPort - extraMapped.Port

	if incDiff > 0 && incDiff < 100 {
		info.Type = NATSymmetricEasyInc
		info.PublicPort = extraMapped.Port
	} else if decDiff > 0 && decDiff < 100 {
		info.Type = NATSymmetricEasyDec
		info.PublicPort = extraMapped.Port
	} else {
		info.Type = NATSymmetricHard
	}

	log.Debug("NAT detected", "type", info.Type, "public_ip", info.PublicIP, "public_port", info.PublicPort)
	return info, nil
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// CreatePunchSocket creates a UDP socket and discovers its public mapping via STUN.
func CreatePunchSocket(stunServer string) (*net.UDPConn, *NATInfo, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}
	mapped, err := stunQuery(conn, stunServer)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("STUN query: %w", err)
	}
	return conn, &NATInfo{
		PublicIP:   mapped.IP.String(),
		PublicPort: mapped.Port,
	}, nil
}

// natObservation records what a remote peer observed as our public address.
type natObservation struct {
	localPort    int     // our local UDP listener port
	observedIP   string  // what the peer sees as our IP
	observedPort int     // what the peer sees as our port
	peerID       peer.ID // who observed this
	at           time.Time
}

// NATDetector detects NAT type using ObservedAddr from existing connections,
// with optional STUN servers as fallback. Results are cached.
type NATDetector struct {
	mu         sync.Mutex
	cachedInfo *NATInfo
	cachedErr  error
	cachedAt   time.Time
	ttl        time.Duration
	failTTL    time.Duration // shorter cache for failures

	// ObservedAddr mode: collect observations from identify events
	host   host.Host
	obsMu  sync.Mutex
	obs    []natObservation
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when collectObservations goroutine exits

	// STUN mode (optional fallback)
	stunServers []string
}

// NewNATDetector creates a detector. If h is non-nil, observations from
// identify events are used for NAT detection. If stunServers is non-empty,
// STUN is used as fallback when observations are insufficient.
func NewNATDetector(h host.Host, stunServers []string, ttl time.Duration) *NATDetector {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &NATDetector{
		host:        h,
		stunServers: stunServers,
		ttl:         ttl,
		failTTL:     1 * time.Minute,
		ctx:         ctx,
		cancel:      cancel,
	}
	if h != nil {
		sub, err := h.EventBus().Subscribe(
			new(event.EvtPeerIdentificationCompleted),
			eventbus.Name("nat-detector"),
		)
		if err != nil {
			log.Debug("nat-detector: failed to subscribe to identify events", "err", err)
		} else {
			d.done = make(chan struct{})
			go d.collectObservations(sub)
		}
	}
	return d
}

// Close stops the observation collector goroutine.
func (d *NATDetector) Close() {
	d.cancel()
	if d.done != nil {
		<-d.done
	}
}

// collectObservations listens for identify completion events and records
// what remote peers observe as our public address.
func (d *NATDetector) collectObservations(sub event.Subscription) {
	defer close(d.done)
	defer sub.Close()
	for {
		select {
		case <-d.ctx.Done():
			return
		case e, ok := <-sub.Out():
			if !ok {
				return
			}
			evt, _ := e.(event.EvtPeerIdentificationCompleted)
			d.recordObservation(evt)
		}
	}
}

func (d *NATDetector) recordObservation(evt event.EvtPeerIdentificationCompleted) {
	conn := evt.Conn
	obsAddr := evt.ObservedAddr
	if conn == nil || obsAddr == nil {
		return
	}
	// Skip relay connections — their observed addr reflects the relay path, not our NAT
	if isRelayAddress(conn.RemoteMultiaddr()) {
		return
	}
	// Also skip if the observed addr itself is a relay address (defensive check:
	// the remote peer could return anything in ObservedAddr, including circuit addrs)
	if isRelayAddress(obsAddr) {
		return
	}
	// Only use UDP-based connections (QUIC) — TCP connections use ephemeral
	// ports per connection, making them useless for NAT type comparison
	localPort := maUDPPort(conn.LocalMultiaddr())
	if localPort == 0 {
		return
	}
	obsIP := maIP(obsAddr)
	obsPort := maUDPPort(obsAddr)
	if obsIP == "" || obsPort == 0 {
		return
	}

	d.obsMu.Lock()
	d.obs = append(d.obs, natObservation{
		localPort:    localPort,
		observedIP:   obsIP,
		observedPort: obsPort,
		peerID:       evt.Peer,
		at:           time.Now(),
	})
	d.obsMu.Unlock()
}

// Detect returns the NAT info, using cache if fresh. Detection order:
// 1. ObservedAddr from existing connections (if host is available)
// 2. STUN servers (if configured, as fallback)
func (d *NATDetector) Detect() (*NATInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return cached success
	if d.cachedInfo != nil && time.Since(d.cachedAt) < d.ttl {
		return d.cachedInfo, nil
	}
	// Return cached failure (shorter TTL)
	if d.cachedErr != nil && !d.cachedAt.IsZero() && time.Since(d.cachedAt) < d.failTTL {
		return nil, d.cachedErr
	}

	// Try ObservedAddr-based detection
	if d.host != nil {
		info, err := d.detectFromObservations()
		if err == nil {
			// Observations now classify sub-types via time-series analysis.
			// Only use STUN refinement if observations couldn't determine the
			// sub-type (returned Hard) and STUN is available — STUN's controlled
			// single-socket probing is more precise for borderline cases.
			if info.Type == NATSymmetricHard && len(d.stunServers) >= 2 {
				stunInfo, stunErr := DetectNAT(d.stunServers)
				if stunErr == nil && stunInfo.Type.IsSymmetric() {
					log.Debug("STUN refined Symmetric sub-type",
						"obs_type", info.Type, "stun_type", stunInfo.Type,
						"stun_port", stunInfo.PublicPort)
					info.Type = stunInfo.Type
					info.PublicPort = stunInfo.PublicPort
				}
			}
			d.cachedInfo = info
			d.cachedErr = nil
			d.cachedAt = time.Now()
			return info, nil
		}
		log.Debug("ObservedAddr NAT detection insufficient", "err", err)
	}

	// Fall back to STUN
	if len(d.stunServers) >= 2 {
		info, err := DetectNAT(d.stunServers)
		if err != nil {
			d.cachedInfo = nil
			d.cachedErr = err
			d.cachedAt = time.Now()
			return nil, err
		}
		d.cachedInfo = info
		d.cachedErr = nil
		d.cachedAt = time.Now()
		return info, nil
	}

	// Neither method has enough data
	err := fmt.Errorf("insufficient data for NAT detection")
	d.cachedInfo = nil
	d.cachedErr = err
	d.cachedAt = time.Now()
	return nil, err
}

// detectFromObservations infers NAT type from identify ObservedAddr data.
// It groups observations by local UDP port and compares what different peers
// see as our mapped port. Requires 2+ observations from different peers
// on the same local port.
func (d *NATDetector) detectFromObservations() (*NATInfo, error) {
	// Collect currently active non-relay peer IDs
	activePeers := make(map[peer.ID]bool)
	for _, conn := range d.host.Network().Conns() {
		if !isRelayAddress(conn.RemoteMultiaddr()) {
			activePeers[conn.RemotePeer()] = true
		}
	}

	d.obsMu.Lock()
	// Filter to observations from active connections only
	active := d.obs[:0]
	for _, o := range d.obs {
		if activePeers[o.peerID] {
			active = append(active, o)
		}
	}
	d.obs = active
	// Copy for analysis under obsMu, then release
	snapshot := make([]natObservation, len(active))
	copy(snapshot, active)
	d.obsMu.Unlock()

	// Group by local port
	byLocalPort := make(map[int]map[peer.ID]natObservation)
	for _, o := range snapshot {
		if byLocalPort[o.localPort] == nil {
			byLocalPort[o.localPort] = make(map[peer.ID]natObservation)
		}
		// Keep latest observation per peer per local port
		if existing, ok := byLocalPort[o.localPort][o.peerID]; !ok || o.at.After(existing.at) {
			byLocalPort[o.localPort][o.peerID] = o
		}
	}

	// Find a group with 2+ unique peers
	for localPort, peerObs := range byLocalPort {
		if len(peerObs) < 2 {
			continue
		}

		var ports []int
		var ip string
		for _, o := range peerObs {
			ports = append(ports, o.observedPort)
			ip = o.observedIP
		}

		// Check if all observed ports are the same → Cone NAT
		allSame := true
		for _, p := range ports[1:] {
			if p != ports[0] {
				allSame = false
				break
			}
		}

		if allSame {
			info := &NATInfo{
				Type:       NATCone,
				PublicIP:   ip,
				PublicPort: ports[0],
			}
			log.Debug("NAT detected from observations", "type", info.Type,
				"public_ip", ip, "public_port", ports[0], "local_port", localPort,
				"observers", len(peerObs))
			return info, nil
		}

		// Ports differ → Symmetric NAT.
		// Analyze the time-ordered port sequence to determine sub-type.
		natType := classifySymmetricSubtype(peerObs)

		// For predictable NATs, use the latest observed port as the base
		// for port prediction (it's closest to the next allocation).
		publicPort := latestObservedPort(peerObs)

		sort.Ints(ports)
		info := &NATInfo{
			Type:       natType,
			PublicIP:   ip,
			PublicPort: publicPort,
		}
		log.Debug("NAT detected from observations", "type", info.Type,
			"public_ip", ip, "observed_ports", ports, "latest_port", publicPort,
			"local_port", localPort, "observers", len(peerObs))
		return info, nil
	}

	return nil, fmt.Errorf("need observations from 2+ peers on same local port, have %d total", len(snapshot))
}

// classifySymmetricSubtype determines the Symmetric NAT sub-type by analyzing
// the observed port distribution. Uses two metrics:
//
//  1. Range/count ratio: sequential allocation produces narrow port ranges
//     (ratio < 30), while random allocation produces wide ranges (ratio >> 30).
//  2. Direction: for narrow ranges, split observations by time into early/late
//     halves and compare average ports to determine Inc vs Dec.
//
// This approach is robust against identify-event timing jitter, which makes
// pure timestamp-ordered analysis unreliable.
func classifySymmetricSubtype(peerObs map[peer.ID]natObservation) NATType {
	if len(peerObs) < 3 {
		return NATSymmetricHard
	}

	obs := make([]natObservation, 0, len(peerObs))
	for _, o := range peerObs {
		obs = append(obs, o)
	}

	// Find port range
	minPort, maxPort := obs[0].observedPort, obs[0].observedPort
	for _, o := range obs[1:] {
		if o.observedPort < minPort {
			minPort = o.observedPort
		}
		if o.observedPort > maxPort {
			maxPort = o.observedPort
		}
	}

	portRange := maxPort - minPort
	if portRange == 0 {
		return NATSymmetricHard // shouldn't happen (caller checks allSame)
	}

	// Sequential allocation: each connection increments port by 1-5, plus
	// interleaved non-libp2p traffic adds gaps. Typical ratio: 3-20.
	// Random allocation: ports scattered across 1-65535. Typical ratio: 500+.
	// Threshold 30 accommodates heavy interleaved traffic on sequential NATs.
	perObsRange := float64(portRange) / float64(len(obs))
	if perObsRange > 30 {
		return NATSymmetricHard
	}

	// Ports are in a narrow band → sequential (predictable) allocation.
	// Determine direction by comparing early vs late observation averages.
	sort.Slice(obs, func(i, j int) bool {
		return obs[i].at.Before(obs[j].at)
	})

	mid := len(obs) / 2
	earlySum, lateSum := 0, 0
	for i := 0; i < mid; i++ {
		earlySum += obs[i].observedPort
	}
	for i := mid; i < len(obs); i++ {
		lateSum += obs[i].observedPort
	}
	earlyAvg := float64(earlySum) / float64(mid)
	lateAvg := float64(lateSum) / float64(len(obs)-mid)

	if lateAvg > earlyAvg {
		return NATSymmetricEasyInc
	}
	return NATSymmetricEasyDec
}

// latestObservedPort returns the observed port from the most recent observation.
// For predictable NATs, this is the best base for port prediction.
func latestObservedPort(peerObs map[peer.ID]natObservation) int {
	var latest natObservation
	for _, o := range peerObs {
		if latest.at.IsZero() || o.at.After(latest.at) {
			latest = o
		}
	}
	return latest.observedPort
}

// Invalidate clears the cached result and observations so the next
// Detect() re-evaluates.
func (d *NATDetector) Invalidate() {
	d.mu.Lock()
	d.cachedInfo = nil
	d.cachedErr = nil
	d.cachedAt = time.Time{}
	d.mu.Unlock()

	d.obsMu.Lock()
	d.obs = nil
	d.obsMu.Unlock()
}

// NATType returns the most recently detected NAT type.
// Returns NATUnknown if detection hasn't completed or failed.
func (d *NATDetector) NATType() NATType {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cachedInfo != nil {
		return d.cachedInfo.Type
	}
	return NATUnknown
}

// STUNServers returns the configured STUN servers (may be empty).
func (d *NATDetector) STUNServers() []string {
	return d.stunServers
}

// HasSTUN returns whether STUN servers are configured.
func (d *NATDetector) HasSTUN() bool {
	return len(d.stunServers) >= 2
}

// maUDPPort extracts the UDP port from a multiaddr. Returns 0 if not present.
func maUDPPort(addr ma.Multiaddr) int {
	if addr == nil {
		return 0
	}
	s, err := addr.ValueForProtocol(ma.P_UDP)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return p
}

// maIP extracts the IP address (v4 or v6) from a multiaddr.
func maIP(addr ma.Multiaddr) string {
	if addr == nil {
		return ""
	}
	if ip, err := addr.ValueForProtocol(ma.P_IP4); err == nil {
		return ip
	}
	if ip, err := addr.ValueForProtocol(ma.P_IP6); err == nil {
		return ip
	}
	return ""
}
