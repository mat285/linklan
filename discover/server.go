package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mat285/linklan/log"
)

var (
	HeloBytes   = []byte{'H', 'E', 'L', 'L', 'O', '\n'}
	AcceptBytes = []byte{'A', 'C', 'E', 'P', 'T', '\n'}
	BeginBytes  = []byte{'B', 'E', 'G', 'I', 'N', '\n'}
	PingBytes   = []byte{'P', 'I', 'N', 'G', '\n'}

	SpeedTestDataSize   int64 = 16 * 1024 * 1024
	SpeedTestInterval         = 60 * time.Second
	SpeedTestBufferSize       = 1024 * 1024

	PingInterval = 1 * time.Second

	MetricName = "link_speed"
)

type Server struct {
	Port int
	IP   string

	lock   sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	peersLock sync.Mutex
	peers     map[byte]map[byte]net.Conn

	knownPeersLock sync.Mutex
	knownPeers     map[string]struct{} // Track known peers to avoid duplicates
}

func NewServer(ip string, port int) *Server {
	return &Server{
		IP:             ip,
		Port:           port,
		peers:          make(map[byte]map[byte]net.Conn),
		knownPeers:     make(map[string]struct{}),
		peersLock:      sync.Mutex{},
		knownPeersLock: sync.Mutex{},
		lock:           sync.Mutex{},
		cancel:         nil,
		done:           nil,
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.cancel != nil {
		return fmt.Errorf("server already running")
	}
	s.lock.Lock()
	log.Default().Info("Starting server on", s.IP, ":", s.Port)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.lock.Unlock()
	go s.SearchForPeers(ctx)
	err := s.Listen(ctx)
	cancel()
	s.lock.Lock()
	s.cancel = nil
	s.done = nil
	s.lock.Unlock()
	close(done)
	log.Default().Info("Server stopped")
	return err
}

func (s *Server) ActivePeers() []string {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	ip := net.ParseIP(s.IP)
	ip[len(ip)-2] = 1
	peers := make([]string, 0, len(s.peers))
	for ipID, lanMap := range s.peers {
		for range lanMap {
			ip[len(ip)-1] = ipID
			peer := ip.String()
			peers = append(peers, peer)
		}
	}
	return peers
}

func (s *Server) SearchForPeers(ctx context.Context) error {
	lan := byte(0)
	log.Default().Info("Starting peer search on LAN ID", lan)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := s.searchWholeLan(ctx, lan)
		if err != nil {
			log.Default().Info("Error searching LAN:", err)
		}
		log.Default().Info("Completed peer search cycle, waiting for next cycle")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(60 * time.Second):
		}
	}
}

func (s *Server) searchWholeLan(ctx context.Context, lan byte) error {
	log.Default().Info("Searching whole LAN with ID", lan)
	localIP := net.ParseIP(s.IP)
	localID := localIP[len(localIP)-1]
	for i := 0; i <= 255; i++ {
		ipID := byte(i)
		if ipID == localID {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		s.peersLock.Lock()
		if _, exists := s.peers[ipID]; !exists {
			s.peers[ipID] = make(map[byte]net.Conn)
		}
		_, exists := s.peers[ipID][lan]
		s.peersLock.Unlock()

		if !exists {
			log.Default().Debug("Trying to ping peer with IP ID", ipID, "and LAN ID", lan)
			err := s.TryPingPeer(ctx, ipID, lan, s.Port)
			if err != nil {
				log.Default().Debug("Failed to ping peer with IP ID", ipID, "and LAN ID", lan, ":", err)
			}
		}
	}
	return nil
}

func (s *Server) Listen(ctx context.Context) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(s.IP, fmt.Sprintf("%d", s.Port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			log.Default().Info("Error accepting connection:", err)
		}
		go s.handlePeerConnection(ctx, conn)
	}
}

func (s *Server) initializeConnectionAsServer(ctx context.Context, conn net.Conn) error {
	log.Default().Info("Handling new peer connection from", conn.RemoteAddr())
	intro := make([]byte, len(HeloBytes))
	r, err := conn.Read(intro)
	if err != nil {
		return err
	}
	if r != len(HeloBytes) || !bytes.Equal(intro, HeloBytes) {
		return err
	}
	log.Default().Info("Received HELO message from peer, processing connection")
	r, err = conn.Write(AcceptBytes)
	if err != nil {
		return err
	}
	if r != len(AcceptBytes) {
		return fmt.Errorf("failed to send ACCEPT message to peer, sent %d bytes, expected %d", r, len(AcceptBytes))
	}
	log.Default().Info("Sent ACCEPT message to peer, processing connection")
	return nil
}

func (s *Server) handlePeerConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	err := s.initializeConnectionAsServer(ctx, conn)
	if err != nil {
		log.Default().Errorf("Error initializing connection as server: %v", err)
		return
	}
	s.handleConnection(ctx, conn)
}

func (s *Server) Stop() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.done != nil {
		close(s.done)
		s.done = nil
	}
	log.Default().Info("Server stopped")
}

func (s *Server) TryPingPeer(ctx context.Context, ipID, lanID byte, port int) error {
	ip := net.ParseIP(s.IP)
	ip[len(ip)-1] = ipID
	log.Default().Debug("Pinging peer at", ip, "on port", port)
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	ip[len(ip)-2] = lanID
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	err = s.initializeConnectionAsClient(ctx, conn)
	if err != nil {
		log.Default().Errorf("%v", err)
		conn.Close()
		return err
	}
	go s.handleConnection(ctx, conn)
	return nil
}

func (s *Server) initializeConnectionAsClient(ctx context.Context, conn net.Conn) error {
	addr := conn.RemoteAddr().String()
	r, err := conn.Write(HeloBytes)
	if err != nil {
		log.Default().Info("Error writing to connection:", err)
		return err
	}
	if r != len(HeloBytes) {
		return fmt.Errorf("failed to send HELO message to %s", addr)
	}
	log.Default().Info("Sent HELO message to", addr, ", waiting for response")

	conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
	acceptBuffer := make([]byte, len(AcceptBytes))
	r, err = conn.Read(acceptBuffer)
	if err != nil {
		return fmt.Errorf("failed to read ACCEPT message from %s: %w", addr, err)
	}
	if r != len(AcceptBytes) || !bytes.Equal(acceptBuffer, AcceptBytes) {
		return fmt.Errorf("invalid ACCEPT message from %s", addr)
	}
	log.Default().Info("Received ACCEPT message from", addr, ", connection established")
	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ip := addressToIP(conn.RemoteAddr().String())
	ipID := ip[len(ip)-1]
	lanID := ip[len(ip)-2]

	s.knownPeersLock.Lock()
	s.knownPeers[ip.String()] = struct{}{}
	s.knownPeersLock.Unlock()

	s.peersLock.Lock()
	if s.peers[ipID] == nil {
		s.peers[ipID] = make(map[byte]net.Conn)
	}

	s.peers[ipID][lanID] = conn
	s.peersLock.Unlock()

	defer func() {
		s.peersLock.Lock()
		delete(s.peers[ipID], lanID)
		if len(s.peers[ipID]) == 0 {
			delete(s.peers, ipID)
		}
		s.peersLock.Unlock()
	}()

	s.handleConnRW(ctx, conn)
}

func (s *Server) handleConnRW(ctx context.Context, conn net.Conn) {
	var rErr, wErr error
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	wg.Add(2)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		defer cancel()
		wErr = s.writeConn(ctx, conn)
		if wErr != nil {
			log.Default().Errorf("Error during write speed test: %v", wErr)
		}
	}(&wg)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		defer cancel()
		rErr = s.readConn(ctx, conn)
		if rErr != nil {
			log.Default().Errorf("Error reading from connection: %v", rErr)
		}
	}(&wg)
	wg.Wait()
	return
}

func (s *Server) writeConn(ctx context.Context, conn net.Conn) error {
	// buffer := make([]byte, SpeedTestBufferSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetWriteDeadline(time.Now().Add(PingInterval))
		n, err := conn.Write(PingBytes)
		if err != nil {
			return err
		}
		if n != len(PingBytes) {
			return fmt.Errorf("failed to write full ping bytes to connection, wrote %d bytes, expected %d", n, len(PingBytes))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(PingInterval):
		}
		// log.Default().Info("Beginning write speed test to connection", conn.RemoteAddr())
		// rand.Read(buffer)
		// count := int64(0)
		// start := time.Now()
		// for count < SpeedTestDataSize {
		// 	n, err := conn.Write(buffer)
		// 	if err != nil {
		// 		log.Default().Info("Error writing to connection:", err)
		// 		return err
		// 	}
		// 	count += int64(n)
		// }
		// speed, mb := calculateSpeed(count, start)
		// log.Default().Infof("Wrote %d bytes to connection, speed: %f Gbps with %d MB of data", count, speed, mb)
		// err := prom.AppendMetric(
		// 	MetricName,
		// 	fmt.Sprintf("%0.4f", speed),
		// 	time.Now(),
		// 	map[string]string{
		// 		"host":   s.IP,
		// 		"remote": addressToIP(conn.RemoteAddr().String()).String(),
		// 	},
		// )
		// if err != nil {
		// 	log.Default().Info("Error appending metric:", err)
		// }
		// select {
		// case <-ctx.Done():
		// 	return ctx.Err()
		// case <-time.After(SpeedTestInterval + time.Duration(mrand.Intn(2000))*time.Millisecond):
		// }
	}
}

func (s *Server) readConn(ctx context.Context, conn net.Conn) error {
	buffer := make([]byte, SpeedTestBufferSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * PingInterval))
		_, err := conn.Read(buffer)
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, io.EOF) {
			log.Default().Info("Error reading from connection:", err)
			return err
		}
	}
}

// func (s *Server) runSpeedTest(ctx context.Context, conn net.Conn, pre func([]byte) (int, error), move func([]byte) (int, error)) {
// 	localIP := net.ParseIP(s.IP)
// 	localIP[len(localIP)-2] = 1
// 	ip := addressToIP(conn.RemoteAddr().String())
// 	rIP := addressToIP(conn.RemoteAddr().String())
// 	rIP[len(rIP)-2] = 1
// 	buffer := make([]byte, SpeedTestBufferSize)
// 	if pre != nil {
// 		_, err := pre(buffer)
// 		if err != nil {
// 			log.Default().Info("Error in pre function:", err)
// 			return
// 		}
// 	}

// 	sent := int64(0)
// 	start := time.Now()

// 	processed := make([]int64, 0)

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		default:
// 		}

// 		n, err := move(buffer)
// 		if err != nil {
// 			log.Default().Info("Error writing to client:", err)
// 			return
// 		}
// 		sent += int64(n)
// 		if sent >= SpeedTestDataSize {
// 			speed, mb := calculateSpeed(sent, start)
// 			log.Default().Infof("Calculated speed of connection with %s: %f Gbps with %d MB of data", ip.String(), speed, mb)
// 			if speed > 0 {
// 				err = prom.AppendMetric(
// 					MetricName,
// 					fmt.Sprintf("%0.4f", speed),
// 					time.Now(),
// 					map[string]string{
// 						"host":   localIP.String(),
// 						"remote": rIP.String(),
// 					},
// 				)
// 			}
// 			if err != nil {
// 				log.Default().Info("Error appending metric:", err)
// 			}

// 			select {
// 			case <-ctx.Done():
// 				return
// 			case <-time.After(SpeedTestInterval):
// 				log.Default().Info("Waiting for next send to client")
// 			}

// 			sent = 0
// 			if pre != nil {
// 				pre(buffer)
// 			}
// 			start = time.Now()
// 		}
// 	}
// }

func calculateSpeed(sent int64, start time.Time) (float64, int64) {
	elapsed := time.Since(start) / time.Nanosecond
	sent = sent * 8
	sentMB := sent / (8 * 1024 * 1024)
	if elapsed == 0 {
		return 0, sentMB
	}
	speed := (float64(sent) / float64(elapsed))
	return speed, sentMB
}

func addressToIP(addr string) net.IP {
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return ip
}
