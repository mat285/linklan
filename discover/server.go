package discover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	mrand "math/rand"
	"net"
	"os"
	"strings"
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

	UDPPayloadPrefix = []byte{'*', '*', '*', 'S', 'L', 'L', '*', '*', '*'}
	UDPPayloadSuffix = []byte{'*', '*', '*', 'E', 'L', 'L', '*', '*', '*'}
	IPAddrSize       = 4

	DialTimeout = 10 * time.Millisecond

	SpeedTestDataSize   int64 = 16 * 1024 * 1024
	SpeedTestInterval         = 60 * time.Second
	SpeedTestBufferSize       = 1024 * 1024

	PingInterval = 1 * time.Second
	PingTimeout  = 3 * time.Second

	MetricName = "link_speed"
)

type udpPing struct {
	IP      net.IP
	RouteIP net.IP
	Iface   string
	Time    time.Time
}

type Server struct {
	Port    int
	LocalIP string
	IP      string

	lock   sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	peersLock sync.Mutex
	peers     map[[4]byte]net.Conn

	knownPeersLock sync.Mutex
	knownPeers     map[string]struct{} // Track known peers to avoid duplicates

	udpPings     map[[4]byte]udpPing // Track recent UDP pings to avoid duplicates
	udpPingsLock sync.Mutex          // Lock for udpPings
}

func NewServer(localIP, listenIP string, port int) *Server {
	return &Server{
		LocalIP:        localIP,
		IP:             listenIP,
		Port:           port,
		peers:          make(map[[4]byte]net.Conn),
		knownPeers:     make(map[string]struct{}),
		udpPings:       make(map[[4]byte]udpPing),
		peersLock:      sync.Mutex{},
		knownPeersLock: sync.Mutex{},
		udpPingsLock:   sync.Mutex{},
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
	err := s.listen(ctx)
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
		case <-time.After(time.Duration(rand.Intn(2500)+60000) * time.Millisecond):
		}
	}
}

func (s *Server) searchWholeLan(ctx context.Context, lan byte) error {
	var err error
	log.GetLogger(ctx).Info("Searching whole LAN with ID", lan)
	localIP := net.ParseIP(s.LocalIP).To4()
	cidrSuffix := "/" + strings.Split(config.GetConfig(ctx).Lan.CIDR, "/")[1]
	localIP, _, err = link.IPForIndex(localIP.String()+cidrSuffix, lan)
	if err != nil {
		return fmt.Errorf("failed to get local IP for LAN ID %d: %w", lan, err)
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

func (s *Server) listen(ctx context.Context) error {
	listenCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tcpListener, err := s.listenNetwork(listenCtx, "tcp4")
	if err != nil {
		log.GetLogger(ctx).Errorf("Failed to listen on tcp4: %v", err)
		return err
	}
	defer tcpListener.Close()

	var wg sync.WaitGroup
	var tcpErr, udpErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer tcpListener.Close()
		tcpErr = s.runListener(listenCtx, "tcp4", tcpListener)
		if tcpErr != nil {
			log.GetLogger(ctx).Errorf("Error running tcp4 listener: %v", tcpErr)
		}
		cancel()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		udpErr = s.listenUDP(listenCtx)
		if udpErr != nil {
			log.GetLogger(ctx).Errorf("Error running UDP listener: %v", udpErr)
		}
		cancel()
	}()

	wg.Wait() // Wait for all listeners to finish
	return errors.Join(tcpErr, udpErr)
}

func (s *Server) listenNetwork(ctx context.Context, network string) (net.Listener, error) {
	return net.Listen(network, net.JoinHostPort(s.IP, fmt.Sprintf("%d", s.Port)))
}

func (s *Server) runListener(ctx context.Context, network string, listener net.Listener) error {
	defer listener.Close()
	log.GetLogger(ctx).Infof("Listening on %s://%s:%d", network, s.IP, s.Port)
	go func() {
		<-ctx.Done()
		log.GetLogger(ctx).Infof("Stopping %s listener", network)
		if err := listener.Close(); err != nil {
			log.GetLogger(ctx).Errorf("Error closing %s listener: %v", network, err)
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
			log.GetLogger(ctx).Infof("Error accepting %s connection: %v", network, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		go s.handleConnection(ctx, link.WrapConn(conn))
	}
}

func (s *Server) listenUDP(ctx context.Context) error {
	addr := net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", s.Port))
	uaddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", addr, err)
	}
	listener, err := net.ListenUDP("udp4", uaddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addr, err)
	}
	defer listener.Close()
	log.GetLogger(ctx).Infof("Listening on UDP %s", uaddr)
	return s.runUDPListener(ctx, listener, nil)
}

func (s *Server) runUDPListener(ctx context.Context, listener *net.UDPConn, buffer []byte) error {
	defer listener.Close()
	if len(buffer) == 0 {
		buffer = make([]byte, 1024)
	}
	log.GetLogger(ctx).Infof("Listening on UDP %s", listener.LocalAddr().String())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fmt.Println("broadcasting UDP packet to all")
			err := s.broadcastUDP(ctx)
			if err != nil {
				log.GetLogger(ctx).Infof("Error broadcasting UDP packet")
			} else {
				log.GetLogger(ctx).Debugf("Broadcasted UDP packet")
			}
			select {
			case <-ctx.Done():
				log.GetLogger(ctx).Infof("Stopping UDP broadcast")
				return
			case <-time.After(5 * time.Second):
				log.GetLogger(ctx).Debugf("Waiting for next UDP broadcast")
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fmt.Println("Reading from UDP listener")
		// listener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				log.GetLogger(ctx).Infof("UDP read deadline exceeded continuing to listen")
				continue
			}
			log.GetLogger(ctx).Infof("Error reading from UDP: %v", err)
			return err
		}
		fmt.Println("Received UDP packet from", addr, "with size", n)
		if addr.IP.To4().String() == s.IP {
			log.GetLogger(ctx).Debugf("Ignoring UDP packet from self %s", addr.IP)
			continue // Ignore packets from self
		}
		//handle packet
		err = s.handleUDPPacket(ctx, buffer[:n])
		if err != nil {
			log.GetLogger(ctx).Infof("Error handling UDP packet from %s: %v", addr, err)
		}
	}
}

func (s *Server) handleUDPPacket(ctx context.Context, packet []byte) error {
	log.GetLogger(ctx).Debugf("Received UDP packet %s", string(packet))
	payload, err := DecodeUDPPacket(packet)
	if err != nil {
		log.GetLogger(ctx).Debugf("Failed to decode UDP packet from %s: %v", "", err)
		return fmt.Errorf("failed to decode UDP packet from %s: %w", "", err)
	}
	if len(payload.PrimaryIP) == 0 {
		log.GetLogger(ctx).Debugf("Received empty primary IP in UDP packet")
		return fmt.Errorf("received empty primary IP in UDP packet")
	}
	primaryIP := net.ParseIP(payload.PrimaryIP)
	if primaryIP == nil {
		log.GetLogger(ctx).Debugf("Failed to parse primary IP %s from UDP packet", payload.PrimaryIP)
		return fmt.Errorf("failed to parse primary IP %s from UDP packet", payload.PrimaryIP)
	}
	log.GetLogger(ctx).Debugf("Received IP packet from %s", primaryIP)

	s.udpPingsLock.Lock()
	defer s.udpPingsLock.Unlock()
	s.udpPings[[4]byte(primaryIP)] = udpPing{
		IP:      primaryIP,
		RouteIP: primaryIP, // Assuming RouteIP is the same as PrimaryIP for now
		Time:    time.Now(),
	}

	for _, secondaryIP := range payload.SecondaryIPs {
		sIP := net.ParseIP(secondaryIP).To4()
		if sIP == nil {
			log.GetLogger(ctx).Debugf("Failed to parse secondary IP %s from UDP packet", secondaryIP)
			continue
		}
		log.GetLogger(ctx).Debugf("Received secondary IP %s from UDP packet", sIP)
		s.udpPings[[4]byte(sIP)] = udpPing{
			IP:      primaryIP,
			RouteIP: sIP, // Assuming RouteIP is the same as SecondaryIP for now
			Time:    time.Now(),
		}
	}
	log.GetLogger(ctx).Debugf("Updated UDP pings with primary IP %s and secondary IPs %v from packet: %s", primaryIP, payload.SecondaryIPs, string(packet))
	return nil
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done
	}
}

func (s *Server) broadcastUDP(ctx context.Context) error {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: s.Port,
	})
	if err != nil {
		return fmt.Errorf("failed to dial UDP broadcast: %w", err)
	}
	defer conn.Close()
	log.GetLogger(ctx).Infof("Broadcasting UDP packet to %s", net.IPv4bcast)
	packet, err := EncodeUDPPacket(s.IP, nil)
	if err != nil {
		return fmt.Errorf("failed to encode UDP packet: %w", err)
	}
	n, err := conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to write UDP packet: %w", err)
	}
	if n != len(packet) {
		return fmt.Errorf("failed to write full UDP packet, wrote %d bytes, expected %d", n, len(packet))
	}
	log.GetLogger(ctx).Debugf("Broadcasted UDP packet to %s", net.IPv4bcast)
	return nil
}

func (s *Server) tryPingPeer(ctx context.Context, ip net.IP, port int) error {
	log.GetLogger(ctx).Debug("Pinging peer at", ip, "on port", port)
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp4", addr, DialTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	lc := link.WrapConn(conn)
	go s.handleConnection(ctx, lc)
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
			lc := link.WrapConn(conn)
			log.GetLogger(ctx).Debugf("Successfully reconnected to peer at %s", addr)
			go s.handleConnection(ctx, lc)
			return nil
		}
		log.GetLogger(ctx).Debugf("Failed to reconnect to peer at %s: %v", addr, err)
	}
	return fmt.Errorf("failed to reconnect to peer with IP %s after %d attempts", ip, maxAttempts)
}

func (s *Server) handleConnection(ctx context.Context, conn *link.Conn) {
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

func (s *Server) addNewConn(ctx context.Context, conn *link.Conn) bool {
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

func (s *Server) cleanupConn(ctx context.Context, conn *link.Conn) {
	ip := [4]byte(addressToIP(conn.RemoteAddr().String()))

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	if s.peers[ip] != conn {
		return
	}
	log.GetLogger(ctx).Infof("Removing closed peer connection from %s", ip)
	delete(s.peers, ip)
}

func (s *Server) handleConnRW(ctx context.Context, conn *link.Conn) {
	var rErr, wErr error
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	wg.Add(2)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		defer cancel()
		wErr = s.writeConn(ctx, conn)
		if wErr != nil {
			log.GetLogger(ctx).Errorf("Error writing to connection: %v", wErr)
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

func (s *Server) writeConn(ctx context.Context, conn *link.Conn) error {
	defer conn.Close()
	log.GetLogger(ctx).Debugf("Starting write loop for connection %s", conn.RemoteAddr().String())
	lastPing := time.Now()
	for {
		if time.Since(lastPing) > PingTimeout {
			log.GetLogger(ctx).Infof("No ping response for %s, closing connection", conn.RemoteAddr().String())
			return fmt.Errorf("no ping response for %s, closing connection", conn.RemoteAddr().String())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(PingInterval):
		}
		if !conn.IsOpen() {
			log.GetLogger(ctx).Infof("Connection %s is closed, stopping write loop", conn.RemoteAddr().String())
			return fmt.Errorf("connection %s is closed, stopping write loop", conn.RemoteAddr().String())
		}
		conn.SetWriteDeadline(time.Now().Add(PingInterval))
		n, err := conn.Write(PingBytes)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return err
			}
			continue
		}
		if n != len(PingBytes) {
			log.GetLogger(ctx).Errorf("failed to write full ping bytes to connection, wrote %d bytes, expected %d", n, len(PingBytes))
			continue
		}
		lastPing = time.Now()
		log.GetLogger(ctx).Debugf("Wrote ping to %s, bytes sent: %d", conn.RemoteAddr().String(), n)
	}
}

func (s *Server) readConn(ctx context.Context, conn *link.Conn) error {
	defer conn.Close()
	log.GetLogger(ctx).Debugf("Starting read loop for connection %s", conn.RemoteAddr().String())
	buffer := make([]byte, SpeedTestBufferSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !conn.IsOpen() {
			log.GetLogger(ctx).Infof("Connection %s is closed, stopping read loop", conn.RemoteAddr().String())
			return fmt.Errorf("connection %s is closed, stopping read loop", conn.RemoteAddr().String())
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
