package discover

import (
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mat285/linklan/config"
	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

var (
	HeloBytes   = []byte{'H', 'E', 'L', 'L', 'O', '\n'}
	AcceptBytes = []byte{'A', 'C', 'E', 'P', 'T', '\n'}
	BeginBytes  = []byte{'B', 'E', 'G', 'I', 'N', '\n'}
	PingBytes   = []byte{'P', 'I', 'N', 'G', '\n'}

	DialTimeout = 10 * time.Millisecond

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
	peers     map[[4]byte]net.Conn

	knownPeersLock sync.Mutex
	knownPeers     map[string]struct{} // Track known peers to avoid duplicates
}

func NewServer(ip string, port int) *Server {
	return &Server{
		IP:             ip,
		Port:           port,
		peers:          make(map[[4]byte]net.Conn),
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
	if s.cancel != nil {
		s.lock.Unlock()
		return fmt.Errorf("server already running")
	}
	log.GetLogger(ctx).Info("Starting server on", s.IP, ":", s.Port)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.lock.Unlock()

	go s.SearchForPeers(ctx)
	err := s.Listen(ctx)
	cancel()
	close(done)
	log.GetLogger(ctx).Info("Server stopped")
	return err
}

func (s *Server) ActivePeers(ctx context.Context) []string {
	localIP, _, err := net.ParseCIDR(config.GetConfig(ctx).Lan.CIDR)
	if err != nil {
		log.GetLogger(context.Background()).Errorf("Failed to parse local CIDR: %v", err)
		return nil
	}
	localIP = localIP.To4()

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	peers := make([]string, 0, len(s.peers))
	for ip := range s.peers {
		peer := make(net.IP, len(localIP))
		copy(peer, localIP)
		peer[len(peer)-1] = ip[len(ip)-1] // Use the last byte of local IP for the peer
		peers = append(peers, peer.String())
	}
	return peers
}

func (s *Server) SearchForPeers(ctx context.Context) error {
	lan := byte(0)
	log.GetLogger(ctx).Info("Starting peer search on LAN ID", lan)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := s.searchWholeLan(ctx, lan)
		if err != nil {
			log.GetLogger(ctx).Info("Error searching LAN:", err)
		}
		log.GetLogger(ctx).Info("Completed peer search cycle, waiting for next cycle")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(60 * time.Second):
		}
	}
}

func (s *Server) searchWholeLan(ctx context.Context, lan byte) error {
	var err error
	log.GetLogger(ctx).Info("Searching whole LAN with ID", lan)
	localIP := net.ParseIP(s.IP).To4()
	cfg := config.GetConfig(ctx)
	if cfg != nil {
		localIP, _, err = link.IPForIndex(cfg.Lan.CIDR, lan)
		if err != nil {
			return fmt.Errorf("failed to get local IP for LAN ID %d: %w", lan, err)
		}
	}
	log.GetLogger(ctx).Infof("Using local IP %s for lan index %d", localIP, lan)
	localID := localIP[len(localIP)-1]
	pingIP := make(net.IP, len(localIP))
	copy(pingIP, localIP)
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
		_, exists := s.peers[[4]byte(pingIP)]
		s.peersLock.Unlock()

		if !exists {
			pingIP[len(pingIP)-1] = byte(i)
			log.GetLogger(ctx).Debugf("Trying to ping peer with IP %s Lan %d", pingIP, lan)
			err := s.tryPingPeer(ctx, pingIP, s.Port)
			if err != nil {
				log.GetLogger(ctx).Debugf("Failed to ping peer with IP %s: %v", pingIP, err)
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
	go func() {
		<-ctx.Done()
		log.GetLogger(ctx).Info("Stopping listener")
		if err := listener.Close(); err != nil {
			log.GetLogger(ctx).Errorf("Error closing listener: %v", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			log.GetLogger(ctx).Info("Error accepting connection:", err)
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done
	}
}

func (s *Server) tryPingPeer(ctx context.Context, ip net.IP, port int) error {
	log.GetLogger(ctx).Debug("Pinging peer at", ip, "on port", port)
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp4", addr, DialTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	go s.handleConnection(ctx, conn)
	return nil
}

func (s *Server) tryReconnect(ctx context.Context, ip net.IP) error {
	log.GetLogger(ctx).Info("Attempting to reconnect to peer with IP ID", ip)
	maxAttempts := 1
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(mrand.Intn(500))*time.Millisecond + time.Duration(1000)*time.Millisecond):
		}

		s.lock.Lock()
		_, exists := s.peers[[4]byte(ip)]
		s.lock.Unlock()

		if exists {
			log.GetLogger(ctx).Debugf("Connection to peer with IP %s  already exists, skipping reconnect", ip)
			return nil
		}

		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", s.Port))
		log.GetLogger(ctx).Debug("Reconnecting to peer at", addr)
		conn, err := net.DialTimeout("tcp4", addr, DialTimeout)
		if err == nil {
			log.GetLogger(ctx).Debugf("Successfully reconnected to peer at %s", addr)
			go s.handleConnection(ctx, conn)
			return nil
		}
		log.GetLogger(ctx).Debugf("Failed to reconnect to peer at %s: %v", addr, err)
	}
	return fmt.Errorf("failed to reconnect to peer with IP %s after %d attempts", ip, maxAttempts)
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ip := addressToIP(conn.RemoteAddr().String())
	log.GetLogger(ctx).Debugf("Handling connection from %s", ip)
	if !s.addNewConn(ctx, conn) {
		log.GetLogger(ctx).Infof("Connection from %s already exists, closing new connection", ip)
		return
	}
	defer s.cleanupConn(ctx, conn)
	defer func() { go s.tryReconnect(ctx, ip) }() // Attempt to reconnect if the connection is closed unexpectedly
	s.handleConnRW(ctx, conn)
}

func (s *Server) addNewConn(ctx context.Context, conn net.Conn) bool {
	ip := addressToIP(conn.RemoteAddr().String())

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.knownPeersLock.Lock()
	defer s.knownPeersLock.Unlock()
	s.knownPeers[ip.String()] = struct{}{}

	if _, exists := s.peers[[4]byte(ip)]; exists {
		log.GetLogger(ctx).Infof("Connection from %s already exists, closing older connection", ip)
		return false
	}
	log.GetLogger(ctx).Infof("Adding new peer connection from %s", ip)
	s.peers[[4]byte(ip)] = conn
	return true
}

func (s *Server) cleanupConn(ctx context.Context, conn net.Conn) {
	ip := [4]byte(addressToIP(conn.RemoteAddr().String()))

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	if s.peers[ip] != conn {
		return
	}
	log.GetLogger(ctx).Infof("Removing closed peer connection from %s", ip)
	delete(s.peers, ip)
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
			log.GetLogger(ctx).Errorf("Error during write speed test: %v", wErr)
		}
	}(&wg)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		defer cancel()
		rErr = s.readConn(ctx, conn)
		if rErr != nil {
			log.GetLogger(ctx).Errorf("Error reading from connection: %v", rErr)
		}
	}(&wg)
	wg.Wait()
}

func (s *Server) writeConn(ctx context.Context, conn net.Conn) error {
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
			log.GetLogger(ctx).Info("Error reading from connection:", err)
			return err
		}
	}
}

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
	return ip.To4()
}
