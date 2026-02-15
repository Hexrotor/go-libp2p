package holepunch

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"
)

// UDPSocketArray manages multiple UDP sockets for hole punching.
type UDPSocketArray struct {
	sockets []*net.UDPConn
}

// NewUDPSocketArray creates n UDP sockets bound to random ports.
func NewUDPSocketArray(n int) (*UDPSocketArray, error) {
	arr := &UDPSocketArray{
		sockets: make([]*net.UDPConn, 0, n),
	}
	for i := 0; i < n; i++ {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			arr.Close()
			return nil, fmt.Errorf("listen socket %d: %w", i, err)
		}
		arr.sockets = append(arr.sockets, conn)
	}
	return arr, nil
}

// SendAll sends data from all sockets to the given address.
func (a *UDPSocketArray) SendAll(data []byte, addr *net.UDPAddr) {
	for _, sock := range a.sockets {
		sock.SetWriteDeadline(time.Now().Add(1 * time.Second))
		sock.WriteTo(data, addr)
	}
}

// Close closes all sockets.
func (a *UDPSocketArray) Close() {
	for _, s := range a.sockets {
		s.Close()
	}
}

// punchSymToCone performs the birthday attack from the Symmetric side
// toward a Cone peer. Creates N sockets, each sends to the Cone peer's
// known public port. The Cone side simultaneously sends to random ports
// on our public IP. Any socket that receives a matching packet → punched.
func punchSymToCone(ctx context.Context, serverAddr *net.UDPAddr, tid uint32) (*PunchedSocket, error) {
	log.Debug("starting SymToCone punch (birthday attack)", "server", serverAddr, "sockets", SymToConeSocketCount)

	arr, err := NewUDPSocketArray(SymToConeSocketCount)
	if err != nil {
		return nil, fmt.Errorf("create socket array: %w", err)
	}

	pkt := MakePunchPacket(tid)
	deadline := time.Now().Add(PunchTimeout)

	type punchedResult struct {
		conn       *net.UDPConn
		remoteAddr *net.UDPAddr
	}
	resultCh := make(chan punchedResult, 1)
	stopListening := make(chan struct{})

	// Persistent listener goroutines (one per socket)
	for _, sock := range arr.sockets {
		go func(s *net.UDPConn) {
			buf := make([]byte, 256)
			for {
				select {
				case <-stopListening:
					return
				case <-ctx.Done():
					return
				default:
				}
				s.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, raddr, err := s.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				if rxTID, ok := ParsePunchPacket(buf[:n]); ok && rxTID == tid {
					select {
					case resultCh <- punchedResult{conn: s, remoteAddr: raddr}:
					default:
					}
					return
				}
			}
		}(sock)
	}

	for round := 0; round < PunchMaxRounds && time.Now().Before(deadline); round++ {
		log.Debug("punch round", "round", round+1, "max", PunchMaxRounds)

		roundEnd := time.Now().Add(PunchRoundDuration)
		for time.Now().Before(roundEnd) && time.Now().Before(deadline) {
			arr.SendAll(pkt, serverAddr)

			select {
			case r := <-resultCh:
				close(stopListening)
				closeSockets(arr.sockets, r.conn)
				log.Debug("punch succeeded (SymToCone)", "local", r.conn.LocalAddr(), "remote", r.remoteAddr)
				return &PunchedSocket{
					Conn:       r.conn,
					LocalAddr:  r.conn.LocalAddr().(*net.UDPAddr),
					RemoteAddr: r.remoteAddr,
				}, nil
			case <-ctx.Done():
				close(stopListening)
				arr.Close()
				return nil, ctx.Err()
			case <-time.After(PunchSendInterval):
			}
		}
	}

	close(stopListening)
	arr.Close()
	return nil, fmt.Errorf("SymToCone punch timeout after %v", PunchTimeout)
}

// punchConeToSym is the Cone side of SymToCone. It sends packets to random ports
// on the Symmetric peer's public IP. After detecting a packet from the Sym side,
// it sends confirmation packets so the Sym side can also detect the punch.
func punchConeToSym(ctx context.Context, serverSocket *net.UDPConn, clientIP net.IP, tid uint32) (*PunchedSocket, error) {
	log.Debug("starting ConeToSym punch (server side)", "client_ip", clientIP)

	pkt := MakePunchPacket(tid)
	shuffledPorts := generateShuffledPorts()
	deadline := time.Now().Add(PunchTimeout)
	portIdx := 0

	type recvResult struct {
		remoteAddr *net.UDPAddr
	}
	recvCh := make(chan recvResult, 1)

	go func() {
		buf := make([]byte, 256)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			serverSocket.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, raddr, err := serverSocket.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if rxTID, ok := ParsePunchPacket(buf[:n]); ok && rxTID == tid {
				select {
				case recvCh <- recvResult{remoteAddr: raddr}:
				default:
				}
				return
			}
		}
	}()

	confirmAndReturn := func(remoteAddr *net.UDPAddr) (*PunchedSocket, error) {
		log.Debug("punch succeeded (ConeToSym server), sending confirmations", "remote", remoteAddr)
		confirmEnd := time.Now().Add(PunchConfirmDuration)
		for time.Now().Before(confirmEnd) {
			serverSocket.SetWriteDeadline(time.Now().Add(1 * time.Second))
			serverSocket.WriteTo(pkt, remoteAddr)
			time.Sleep(PunchConfirmInterval)
		}
		return &PunchedSocket{
			Conn:       serverSocket,
			LocalAddr:  serverSocket.LocalAddr().(*net.UDPAddr),
			RemoteAddr: remoteAddr,
		}, nil
	}

	for round := 0; round < PunchMaxRounds && time.Now().Before(deadline); round++ {
		packetsThisRound := randomInt(BirthdayMinPackets, BirthdayMaxPackets)
		log.Debug("server punch round", "round", round+1, "max", PunchMaxRounds, "packets", packetsThisRound)

		for i := 0; i < packetsThisRound && time.Now().Before(deadline); i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			if portIdx >= len(shuffledPorts) {
				portIdx = 0
			}
			dstAddr := &net.UDPAddr{IP: clientIP, Port: shuffledPorts[portIdx]}
			portIdx++

			serverSocket.SetWriteDeadline(time.Now().Add(1 * time.Second))
			serverSocket.WriteTo(pkt, dstAddr)

			if i%100 == 99 {
				select {
				case r := <-recvCh:
					return confirmAndReturn(r.remoteAddr)
				default:
				}
			}
		}

		select {
		case r := <-recvCh:
			return confirmAndReturn(r.remoteAddr)
		case <-time.After(1 * time.Second):
		}
	}

	return nil, fmt.Errorf("ConeToSym server punch timeout")
}

// punchBothEasySym performs port-prediction based punching for two Easy Symmetric NATs.
func punchBothEasySym(
	ctx context.Context,
	peerAddr *net.UDPAddr,
	myIncremental bool,
	peerIncremental bool,
	myCurrentPort int,
	tid uint32,
) (*PunchedSocket, error) {
	log.Debug("starting BothEasySym punch", "peer", peerAddr, "my_inc", myIncremental, "peer_inc", peerIncremental)

	predictedPeerPort := peerAddr.Port
	if peerIncremental {
		predictedPeerPort += EasySymPortOffset
	} else {
		predictedPeerPort -= EasySymPortOffset
	}
	targetAddr := &net.UDPAddr{IP: peerAddr.IP, Port: predictedPeerPort}

	arr, err := NewUDPSocketArray(BothEasySymSocketCount)
	if err != nil {
		return nil, fmt.Errorf("create socket array: %w", err)
	}

	pkt := MakePunchPacket(tid)
	deadline := time.Now().Add(PunchTimeout)

	type punchedResult struct {
		conn       *net.UDPConn
		remoteAddr *net.UDPAddr
	}
	resultCh := make(chan punchedResult, 1)
	stopListening := make(chan struct{})

	for _, sock := range arr.sockets {
		go func(s *net.UDPConn) {
			buf := make([]byte, 256)
			for {
				select {
				case <-stopListening:
					return
				case <-ctx.Done():
					return
				default:
				}
				s.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, raddr, err := s.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				if rxTID, ok := ParsePunchPacket(buf[:n]); ok && rxTID == tid {
					select {
					case resultCh <- punchedResult{conn: s, remoteAddr: raddr}:
					default:
					}
					return
				}
			}
		}(sock)
	}

	for time.Now().Before(deadline) {
		arr.SendAll(pkt, targetAddr)

		select {
		case r := <-resultCh:
			close(stopListening)
			closeSockets(arr.sockets, r.conn)
			log.Debug("punch succeeded (BothEasySym)", "local", r.conn.LocalAddr(), "remote", r.remoteAddr)
			return &PunchedSocket{
				Conn:       r.conn,
				LocalAddr:  r.conn.LocalAddr().(*net.UDPAddr),
				RemoteAddr: r.remoteAddr,
			}, nil
		case <-ctx.Done():
			close(stopListening)
			arr.Close()
			return nil, ctx.Err()
		case <-time.After(PunchSendInterval):
		}
	}

	close(stopListening)
	arr.Close()
	return nil, fmt.Errorf("BothEasySym punch timeout")
}

// punchConeToCone performs a simple punch between two Cone NATs.
func punchConeToCone(ctx context.Context, mySocket *net.UDPConn, peerAddr *net.UDPAddr, tid uint32) (*PunchedSocket, error) {
	log.Debug("starting ConeToCone punch", "peer", peerAddr)

	pkt := MakePunchPacket(tid)
	deadline := time.Now().Add(PunchTimeout)

	type recvResult struct {
		remoteAddr *net.UDPAddr
	}
	recvCh := make(chan recvResult, 1)

	go func() {
		buf := make([]byte, 256)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			mySocket.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, raddr, err := mySocket.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if rxTID, ok := ParsePunchPacket(buf[:n]); ok && rxTID == tid {
				select {
				case recvCh <- recvResult{remoteAddr: raddr}:
				default:
				}
				return
			}
		}
	}()

	for time.Now().Before(deadline) {
		mySocket.SetWriteDeadline(time.Now().Add(1 * time.Second))
		mySocket.WriteTo(pkt, peerAddr)

		select {
		case r := <-recvCh:
			log.Debug("punch succeeded (ConeToCone)", "remote", r.remoteAddr)
			return &PunchedSocket{
				Conn:       mySocket,
				LocalAddr:  mySocket.LocalAddr().(*net.UDPAddr),
				RemoteAddr: r.remoteAddr,
			}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(PunchSendInterval):
		}
	}

	return nil, fmt.Errorf("ConeToCone punch timeout")
}

// ExecutePunch runs the appropriate punch strategy based on method and NAT types.
func ExecutePunch(
	ctx context.Context,
	myNAT *NATInfo,
	peerNAT *NATInfo,
	method PunchMethod,
	tid uint32,
	punchSock *net.UDPConn,
) (*PunchedSocket, error) {
	peerAddr := &net.UDPAddr{
		IP:   net.ParseIP(peerNAT.PublicIP),
		Port: peerNAT.PublicPort,
	}

	switch method {
	case PunchConeToCone:
		if punchSock == nil {
			return nil, fmt.Errorf("ConeToCone requires a punch socket")
		}
		return punchConeToCone(ctx, punchSock, peerAddr, tid)

	case PunchSymToCone:
		if myNAT.Type.IsSymmetric() {
			return punchSymToCone(ctx, peerAddr, tid)
		}
		if punchSock == nil {
			return nil, fmt.Errorf("ConeToSym requires a punch socket")
		}
		return punchConeToSym(ctx, punchSock, net.ParseIP(peerNAT.PublicIP), tid)

	case PunchEasySymToEasySym:
		return punchBothEasySym(
			ctx, peerAddr,
			myNAT.Type == NATSymmetricEasyInc,
			peerNAT.Type == NATSymmetricEasyInc,
			myNAT.PublicPort, tid,
		)

	default:
		return nil, fmt.Errorf("unsupported punch method: %d", method)
	}
}

// Helper functions

func generateShuffledPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	for i := len(ports) - 1; i > 0; i-- {
		j := randomInt(0, i+1)
		ports[i], ports[j] = ports[j], ports[i]
	}
	return ports
}

func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return int(n.Int64()) + min
}

func closeSockets(sockets []*net.UDPConn, keep *net.UDPConn) {
	for _, s := range sockets {
		if s != keep {
			s.Close()
		}
	}
}
