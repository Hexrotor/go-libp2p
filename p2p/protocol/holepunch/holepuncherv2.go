package holepunch

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch/pb"
	"github.com/libp2p/go-msgio/pbio"
	ma "github.com/multiformats/go-multiaddr"
)

// directConnectV2 attempts a DCUtR v2 hole punch with the remote peer.
// It opens a v2 stream, exchanges NAT info, performs UDP-level punching
// (or standard simultaneous connect for ConeToCone), then establishes
// a direct connection.
func (hp *holePuncher) directConnectV2(rp peer.ID) error {
	hpCtx := network.WithAllowLimitedConn(hp.ctx, "hole-punch-v2")
	sCtx := network.WithNoDial(hpCtx, "hole-punch-v2")
	str, err := hp.host.NewStream(sCtx, rp, ProtocolV2)
	if err != nil {
		return fmt.Errorf("v2 stream: %w", err)
	}
	defer str.Close()

	punched, rtt, peerAddrs, err := hp.initiateHolePunchV2(str, rp)
	if err != nil {
		str.Reset()
		return err
	}

	if punched != nil {
		// Got a punched UDP socket → establish QUIC on it
		remoteMA, err := udpAddrToQuicMultiaddr(punched.RemoteAddr)
		if err != nil {
			punched.Conn.Close()
			return fmt.Errorf("bad remote addr: %w", err)
		}

		punchCtx := network.WithPunchedSocket(hp.ctx, &network.PunchedSocketInfo{
			Conn:       punched.Conn,
			RemoteAddr: punched.RemoteAddr,
		})

		pi := peer.AddrInfo{ID: rp, Addrs: []ma.Multiaddr{remoteMA}}
		hp.tracer.StartHolePunch(rp, pi.Addrs, rtt)
		hp.tracer.HolePunchAttempt(rp)
		start := time.Now()

		ctx, cancel := context.WithTimeout(punchCtx, hp.directDialTimeout)
		err = holePunchConnect(ctx, hp.host, pi, true) // initiator = QUIC client
		cancel()

		dt := time.Since(start)
		hp.tracer.EndHolePunch(rp, dt, err)

		if err != nil {
			punched.Conn.Close()
			return fmt.Errorf("QUIC on punched socket: %w", err)
		}

		log.Debug("v2 hole punch successful (punched socket)", "peer", rp, "duration", dt)
		return nil
	}

	// ConeToCone path: no UDP punch needed, use standard simultaneous connect
	if len(peerAddrs) > 0 {
		pi := peer.AddrInfo{ID: rp, Addrs: peerAddrs}
		hp.tracer.StartHolePunch(rp, peerAddrs, rtt)
		hp.tracer.HolePunchAttempt(rp)
		start := time.Now()

		ctx, cancel := context.WithTimeout(hp.ctx, hp.directDialTimeout)
		err = holePunchConnect(ctx, hp.host, pi, true)
		cancel()

		dt := time.Since(start)
		hp.tracer.EndHolePunch(rp, dt, err)

		if err != nil {
			return fmt.Errorf("v2 ConeToCone connect: %w", err)
		}
		log.Debug("v2 hole punch successful (ConeToCone)", "peer", rp, "duration", dt)
		return nil
	}

	return fmt.Errorf("v2 hole punch: no punched socket and no peer addresses")
}

// initiateHolePunchV2 performs the v2 protocol exchange over a DCUtR stream
// and then executes the UDP-level punch (or skips it for ConeToCone).
// Returns: punched socket (nil for ConeToCone), RTT, peer's observed addresses, error.
func (hp *holePuncher) initiateHolePunchV2(str network.Stream, rp peer.ID) (*PunchedSocket, time.Duration, []ma.Multiaddr, error) {
	if err := str.Scope().SetService(ServiceName); err != nil {
		return nil, 0, nil, fmt.Errorf("error attaching stream to holepunch service: %s", err)
	}
	if err := str.Scope().ReserveMemory(maxMsgSize, network.ReservationPriorityAlways); err != nil {
		return nil, 0, nil, fmt.Errorf("error reserving memory for stream: %s", err)
	}
	defer str.Scope().ReleaseMemory(maxMsgSize)

	w := pbio.NewDelimitedWriter(str)
	rd := pbio.NewDelimitedReader(str, maxMsgSize)
	str.SetDeadline(time.Now().Add(StreamTimeout))

	// Detect own NAT
	myNAT, err := hp.natDetector.Detect()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("NAT detection failed: %w", err)
	}

	// Create punch socket and STUN query if Cone NAT and STUN is available
	var punchSock *net.UDPConn
	var punchInfo *NATInfo
	if myNAT.Type.IsCone() && hp.natDetector.HasSTUN() {
		sock, info, err := CreatePunchSocket(hp.natDetector.STUNServers()[0])
		if err != nil {
			log.Debug("failed to create punch socket", "err", err)
		} else {
			punchSock = sock
			punchInfo = info
		}
	}

	// Build CONNECT message with NAT info
	obsAddrs := removeRelayAddrs(hp.listenAddrs())
	if hp.filter != nil {
		obsAddrs = hp.filter.FilterLocal(rp, obsAddrs)
	}
	if len(obsAddrs) == 0 {
		closePunchSock(punchSock)
		return nil, 0, nil, errors.New("aborting v2 hole punch: no public address")
	}

	natPB := NATTypeToPB(myNAT.Type)
	connectMsg := &pb.HolePunch{
		Type:     pb.HolePunch_CONNECT.Enum(),
		ObsAddrs: addrsToBytes(obsAddrs),
		NatType:  &natPB,
	}
	if punchInfo != nil {
		punchMA, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", punchInfo.PublicIP, punchInfo.PublicPort))
		if punchMA != nil {
			connectMsg.PunchAddrs = addrsToBytes([]ma.Multiaddr{punchMA})
		}
		port := uint32(punchInfo.PublicPort)
		connectMsg.PublicPort = &port
	} else {
		port := uint32(myNAT.PublicPort)
		connectMsg.PublicPort = &port
	}

	log.Debug("v2 initiating hole punch", "peer", rp, "my_nat", myNAT.Type, "obs_addrs", obsAddrs)

	// Send CONNECT and start RTT measurement
	start := time.Now()
	if err := w.WriteMsg(connectMsg); err != nil {
		closePunchSock(punchSock)
		return nil, 0, nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	// Read CONNECT response
	var resp pb.HolePunch
	if err := rd.ReadMsg(&resp); err != nil {
		closePunchSock(punchSock)
		return nil, 0, nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	rtt := time.Since(start)

	if resp.GetType() != pb.HolePunch_CONNECT {
		closePunchSock(punchSock)
		return nil, 0, nil, fmt.Errorf("expected CONNECT response, got %s", resp.GetType())
	}

	// Extract peer's NAT info
	peerNATType := NATTypeFromPB(resp.GetNatType())
	peerNAT := &NATInfo{
		Type:       peerNATType,
		PublicPort: int(resp.GetPublicPort()),
	}

	peerPunchAddrs := addrsFromBytes(resp.GetPunchAddrs())
	if len(peerPunchAddrs) > 0 {
		if ip, err := peerPunchAddrs[0].ValueForProtocol(ma.P_IP4); err == nil {
			peerNAT.PublicIP = ip
		}
		if portStr, err := peerPunchAddrs[0].ValueForProtocol(ma.P_UDP); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && peerNAT.PublicPort == 0 {
				peerNAT.PublicPort = port
			}
		}
	}
	if peerNAT.PublicIP == "" {
		// Fallback: get IP from ObsAddrs
		for _, a := range removeRelayAddrs(addrsFromBytes(resp.GetObsAddrs())) {
			if ip, err := a.ValueForProtocol(ma.P_IP4); err == nil {
				peerNAT.PublicIP = ip
				break
			}
		}
	}

	// Collect peer's observed addresses for ConeToCone fallback
	peerObsAddrs := removeRelayAddrs(addrsFromBytes(resp.GetObsAddrs()))

	// Determine punch method
	method := DeterminePunchMethod(myNAT.Type, peerNATType)
	if method == PunchNone {
		closePunchSock(punchSock)
		return nil, rtt, nil, fmt.Errorf("no viable punch method for %s <-> %s", myNAT.Type, peerNATType)
	}

	log.Debug("v2 punch method determined", "my_nat", myNAT.Type, "peer_nat", peerNATType,
		"method", method, "peer_ip", peerNAT.PublicIP, "peer_port", peerNAT.PublicPort, "rtt", rtt)

	// Generate TID and send SYNC
	tidVal := generateRandomTID()
	if err := w.WriteMsg(&pb.HolePunch{
		Type: pb.HolePunch_SYNC.Enum(),
		Tid:  &tidVal,
	}); err != nil {
		closePunchSock(punchSock)
		return nil, rtt, nil, fmt.Errorf("failed to send SYNC: %w", err)
	}

	// Wait RTT/2 for sync to propagate to remote peer
	synTime := rtt / 2
	timer := time.NewTimer(synTime)
	select {
	case <-timer.C:
	case <-hp.ctx.Done():
		timer.Stop()
		closePunchSock(punchSock)
		return nil, rtt, nil, hp.ctx.Err()
	}

	// ConeToCone without punch socket: skip UDP punch, return peer addrs
	// for standard simultaneous connect (both sides have endpoint-independent
	// mapping, so standard QUIC dial works)
	if method == PunchConeToCone && punchSock == nil {
		log.Debug("v2 ConeToCone without punch socket, using simultaneous connect",
			"peer", rp, "peer_addrs", peerObsAddrs)
		return nil, rtt, peerObsAddrs, nil
	}

	// Execute UDP punch
	punchCtx, cancel := context.WithTimeout(hp.ctx, PunchTimeout)
	defer cancel()

	punched, err := ExecutePunch(punchCtx, myNAT, peerNAT, method, tidVal, punchSock)
	if err != nil {
		closePunchSock(punchSock)
		return nil, rtt, nil, fmt.Errorf("UDP punch failed: %w", err)
	}

	return punched, rtt, nil, nil
}

// udpAddrToQuicMultiaddr converts a net.UDPAddr to a /ip4/.../udp/.../quic-v1 multiaddr.
func udpAddrToQuicMultiaddr(addr *net.UDPAddr) (ma.Multiaddr, error) {
	if ip4 := addr.IP.To4(); ip4 != nil {
		return ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", ip4.String(), addr.Port))
	}
	return ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/udp/%d/quic-v1", addr.IP.String(), addr.Port))
}

// generateRandomTID generates a random 32-bit transaction ID.
func generateRandomTID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// closePunchSock safely closes a punch socket if non-nil.
func closePunchSock(sock *net.UDPConn) {
	if sock != nil {
		sock.Close()
	}
}
