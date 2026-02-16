package holepunch

import (
	"context"
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

// handleNewStreamV2 handles incoming DCUtR v2 streams (receiver side).
func (s *Service) handleNewStreamV2(str network.Stream) {
	// Check directionality: the receiver sees the underlying connection as outbound.
	if str.Conn().Stat().Direction == network.DirInbound {
		str.Reset()
		return
	}

	if err := str.Scope().SetService(ServiceName); err != nil {
		log.Debug("error attaching v2 stream to holepunch service", "err", err)
		str.Reset()
		return
	}

	rp := str.Conn().RemotePeer()
	rtt, punchedSock, ownAddrs, peerAddrs, err := s.incomingHolePunchV2(str)
	if err != nil {
		s.tracer.ProtocolError(rp, err)
		log.Debug("error handling v2 holepunching stream", "peer", rp, "err", err)
		str.Reset()
		return
	}
	str.Close()

	if punchedSock != nil {
		// Got a punched UDP socket → establish QUIC on it
		remoteMA, err := udpAddrToQuicMultiaddr(punchedSock.RemoteAddr)
		if err != nil {
			punchedSock.Conn.Close()
			log.Debug("v2 bad remote addr", "peer", rp, "err", err)
			return
		}

		punchCtx := network.WithPunchedSocket(s.ctx, &network.PunchedSocketInfo{
			Conn:       punchedSock.Conn,
			RemoteAddr: punchedSock.RemoteAddr,
		})

		pi := peer.AddrInfo{
			ID:    rp,
			Addrs: []ma.Multiaddr{remoteMA},
		}
		s.tracer.StartHolePunch(rp, pi.Addrs, rtt)
		log.Debug("v2 starting QUIC on punched socket", "peer", rp)
		start := time.Now()
		s.tracer.HolePunchAttempt(pi.ID)
		ctx, cancel := context.WithTimeout(punchCtx, s.directDialTimeout)
		err = holePunchConnect(ctx, s.host, pi, false) // receiver = QUIC server
		cancel()
		dt := time.Since(start)
		s.tracer.EndHolePunch(rp, dt, err)

		if err != nil {
			punchedSock.Conn.Close()
			log.Debug("v2 QUIC on punched socket failed", "peer", rp, "err", err)
		}
		s.tracer.HolePunchFinished("receiver-v2", 1, pi.Addrs, ownAddrs, getDirectConnection(s.host, rp))
		return
	}

	// ConeToCone path: no UDP punch needed, use standard simultaneous connect
	if len(peerAddrs) > 0 {
		pi := peer.AddrInfo{ID: rp, Addrs: peerAddrs}
		s.tracer.StartHolePunch(rp, peerAddrs, rtt)
		log.Debug("v2 ConeToCone simultaneous connect (receiver)", "peer", rp, "addrs", peerAddrs)
		start := time.Now()
		s.tracer.HolePunchAttempt(rp)
		ctx, cancel := context.WithTimeout(s.ctx, s.directDialTimeout)
		err = holePunchConnect(ctx, s.host, pi, false) // receiver = QUIC server
		cancel()
		dt := time.Since(start)
		s.tracer.EndHolePunch(rp, dt, err)

		if err != nil {
			log.Debug("v2 ConeToCone connect failed (receiver)", "peer", rp, "err", err)
		}
		s.tracer.HolePunchFinished("receiver-v2", 1, peerAddrs, ownAddrs, getDirectConnection(s.host, rp))
		return
	}

	log.Debug("v2 hole punch: no punched socket and no peer addresses", "peer", rp)
}

// incomingHolePunchV2 handles the v2 protocol exchange from the receiver side.
// It reads the initiator's CONNECT, responds with its own NAT info,
// reads SYNC with TID, then executes the UDP punch (or skips it for ConeToCone).
// Returns: rtt, punched socket (nil for ConeToCone), own addrs, peer's addrs, error.
func (s *Service) incomingHolePunchV2(str network.Stream) (rtt time.Duration, punchedSock *PunchedSocket, ownAddrs []ma.Multiaddr, peerAddrs []ma.Multiaddr, err error) {
	// Sanity check: hole punch request should come from peers behind a relay
	if !isRelayAddress(str.Conn().RemoteMultiaddr()) {
		return 0, nil, nil, nil, fmt.Errorf("received v2 hole punch from non-relay: %s", str.Conn().RemoteMultiaddr())
	}

	ownAddrs = s.listenAddrs()
	if s.filter != nil {
		ownAddrs = s.filter.FilterLocal(str.Conn().RemotePeer(), ownAddrs)
	}
	if len(ownAddrs) == 0 {
		return 0, nil, nil, nil, errors.New("rejecting v2 hole punch: no public addresses")
	}

	if err := str.Scope().ReserveMemory(maxMsgSize, network.ReservationPriorityAlways); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("error reserving memory: %w", err)
	}
	defer str.Scope().ReleaseMemory(maxMsgSize)

	wr := pbio.NewDelimitedWriter(str)
	rd := pbio.NewDelimitedReader(str, maxMsgSize)
	str.SetDeadline(time.Now().Add(StreamTimeout))

	// Read CONNECT from initiator
	var msg pb.HolePunch
	if err := rd.ReadMsg(&msg); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to read CONNECT from initiator: %w", err)
	}
	if msg.GetType() != pb.HolePunch_CONNECT {
		return 0, nil, nil, nil, fmt.Errorf("expected CONNECT, got %s", msg.GetType())
	}

	// Extract initiator's NAT info
	initiatorNATType := NATTypeFromPB(msg.GetNatType())
	initiatorNAT := &NATInfo{
		Type:       initiatorNATType,
		PublicPort: int(msg.GetPublicPort()),
	}
	initiatorPunchAddrs := addrsFromBytes(msg.GetPunchAddrs())
	if len(initiatorPunchAddrs) > 0 {
		if ip, err := initiatorPunchAddrs[0].ValueForProtocol(ma.P_IP4); err == nil {
			initiatorNAT.PublicIP = ip
		}
		if portStr, err := initiatorPunchAddrs[0].ValueForProtocol(ma.P_UDP); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && initiatorNAT.PublicPort == 0 {
				initiatorNAT.PublicPort = port
			}
		}
	}
	if initiatorNAT.PublicIP == "" {
		for _, a := range removeRelayAddrs(addrsFromBytes(msg.GetObsAddrs())) {
			if ip, err := a.ValueForProtocol(ma.P_IP4); err == nil {
				initiatorNAT.PublicIP = ip
				break
			}
		}
	}

	// Collect initiator's observed addresses for ConeToCone fallback
	initiatorObsAddrs := removeRelayAddrs(addrsFromBytes(msg.GetObsAddrs()))

	log.Debug("v2 received CONNECT", "peer", str.Conn().RemotePeer(),
		"initiator_nat", initiatorNATType, "initiator_ip", initiatorNAT.PublicIP,
		"initiator_port", initiatorNAT.PublicPort)

	// Detect own NAT
	if s.natDetector == nil {
		return 0, nil, nil, nil, errors.New("v2 hole punch: NAT detector not configured")
	}
	myNAT, err := s.natDetector.Detect()
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("NAT detection failed: %w", err)
	}

	// Create punch socket if Cone and STUN is available
	var punchSock *net.UDPConn
	var punchInfo *NATInfo
	if myNAT.Type.IsCone() && s.natDetector.HasSTUN() {
		sock, info, sErr := CreatePunchSocket(s.natDetector.STUNServers()[0])
		if sErr != nil {
			log.Debug("failed to create punch socket", "err", sErr)
		} else {
			punchSock = sock
			punchInfo = info
		}
	}

	// Build and send CONNECT response
	natPB := NATTypeToPB(myNAT.Type)
	respMsg := &pb.HolePunch{
		Type:     pb.HolePunch_CONNECT.Enum(),
		ObsAddrs: addrsToBytes(ownAddrs),
		NatType:  &natPB,
	}
	if punchInfo != nil {
		punchMA, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", punchInfo.PublicIP, punchInfo.PublicPort))
		if punchMA != nil {
			respMsg.PunchAddrs = addrsToBytes([]ma.Multiaddr{punchMA})
		}
		port := uint32(punchInfo.PublicPort)
		respMsg.PublicPort = &port
	} else {
		// No punch socket (e.g. Symmetric side), but still include detected
		// public IP so the peer can target us correctly for birthday attack.
		if myNAT.PublicIP != "" && myNAT.PublicPort > 0 {
			punchMA, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", myNAT.PublicIP, myNAT.PublicPort))
			if punchMA != nil {
				respMsg.PunchAddrs = addrsToBytes([]ma.Multiaddr{punchMA})
			}
		}
		port := uint32(myNAT.PublicPort)
		respMsg.PublicPort = &port
	}

	tstart := time.Now()
	if err := wr.WriteMsg(respMsg); err != nil {
		closePunchSock(punchSock)
		return 0, nil, nil, nil, fmt.Errorf("failed to send CONNECT response: %w", err)
	}

	// Read SYNC from initiator
	msg.Reset()
	if err := rd.ReadMsg(&msg); err != nil {
		closePunchSock(punchSock)
		return 0, nil, nil, nil, fmt.Errorf("failed to read SYNC: %w", err)
	}
	rtt = time.Since(tstart)
	if msg.GetType() != pb.HolePunch_SYNC {
		closePunchSock(punchSock)
		return 0, nil, nil, nil, fmt.Errorf("expected SYNC, got %s", msg.GetType())
	}
	tid := msg.GetTid()

	// Determine punch method
	method := DeterminePunchMethod(initiatorNATType, myNAT.Type)
	if method == PunchNone {
		closePunchSock(punchSock)
		return rtt, nil, ownAddrs, nil, fmt.Errorf("no viable punch method for %s <-> %s", initiatorNATType, myNAT.Type)
	}

	log.Debug("v2 receiver punch", "peer", str.Conn().RemotePeer(),
		"my_nat", myNAT.Type, "initiator_nat", initiatorNATType,
		"method", method, "tid", tid, "rtt", rtt)

	// ConeToCone: always use standard simultaneous QUIC connect.
	// Both sides have endpoint-independent mapping, so raw UDP punch is
	// unnecessary and adds timing complexity. Close punch socket if present.
	if method == PunchConeToCone {
		closePunchSock(punchSock)
		log.Debug("v2 ConeToCone using simultaneous connect (receiver)",
			"peer", str.Conn().RemotePeer(), "initiator_addrs", initiatorObsAddrs)
		return rtt, nil, ownAddrs, initiatorObsAddrs, nil
	}

	// Execute UDP punch
	punchCtx, cancel := context.WithTimeout(s.ctx, PunchTimeout)
	defer cancel()

	punched, err := ExecutePunch(punchCtx, myNAT, initiatorNAT, method, tid, punchSock)
	if err != nil {
		closePunchSock(punchSock)
		return rtt, nil, ownAddrs, nil, fmt.Errorf("UDP punch failed: %w", err)
	}

	return rtt, punched, ownAddrs, nil, nil
}
