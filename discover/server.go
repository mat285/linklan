package discover

import (
	"context"
	"errors"
	"fmt"
	"io"
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

	UDPIPPayloadPrefix = []byte{'*', '*', '*', 'I', 'P', '*', '*', '*'}
	IPAddrSize         = 4

	DialTimeout = 10 * time.Millisecond

	SpeedTestDataSize   int64 = 16 * 1024 * 1024
	SpeedTestInterval         = 60 * time.Second
	SpeedTestBufferSize       = 1024 * 1024

	PingInterval = 5 * time.Second

	MetricName = "link_speed"
)

type udpPing struct {
	IP      net.IP
	RouteIP net.IP
	Iface   string
	Time    time.Time
}

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

	udpPings     map[[4]byte]udpPing // Track recent UDP pings to avoid duplicates
	udpPingsLock sync.Mutex          // Lock for udpPings
}

func NewServer(ip string, port int) *Server {
	return &Server{
		IP:             ip,
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
		udpErr = s.listenAllUDP(listenCtx)
		if udpErr != nil {
			log.GetLogger(ctx).Errorf("Error running UDP listener: %v", udpErr)
		}
		cancel()
	}()

	wg.Wait() // Wait for all listeners to finish
	return errors.Join(tcpErr, udpErr)
	// networks := []string{"udp4", "tcp4"}
	// listeners := make([]net.Listener, 0, len(networks))

	// errChan := make(chan error, len(networks))
	// log.GetLogger(ctx).Info("Starting server listeners")
	// for _, network := range networks {
	// 	listener, err := s.listenNetwork(ctx, network)
	// 	if err != nil {
	// 		log.GetLogger(ctx).Errorf("Failed to listen on %s: %v", network, err)
	// 		cancel() // Cancel the context to stop all listeners
	// 		return err
	// 	}
	// 	defer listener.Close()
	// 	listeners = append(listeners, listener)
	// 	go func(ctx context.Context, network string, listener net.Listener) {
	// 		err := s.runListener(ctx, network, listener)
	// 		log.GetLogger(ctx).Errorf("Error listening on %s: %v", network, err)
	// 		errChan <- err
	// 	}(listenCtx, network, listener)
	// }
	// finished := 0
	// errs := make([]error, 0, len(networks)+1)
	// select {
	// case <-ctx.Done():
	// 	log.GetLogger(ctx).Info("Server context done, stopping listeners")
	// 	errs = append(errs, ctx.Err())
	// case err := <-errChan:
	// 	finished++
	// 	if err != nil {
	// 		errs = append(errs, err)
	// 	}
	// }
	// cancel() // Cancel the context to stop all listeners
	// for _, listener := range listeners {
	// 	if err := listener.Close(); err != nil {
	// 		log.GetLogger(ctx).Errorf("Error closing listener: %v", err)
	// 	}
	// }
	// for finished < len(networks) {
	// 	err := <-errChan // Wait for all listeners to finish
	// 	finished++
	// 	if err != nil {
	// 		log.GetLogger(ctx).Errorf("Error in server listener: %v", err)
	// 		errs = append(errs, err)
	// 	}
	// }
	// if len(errs) > 0 {
	// 	return fmt.Errorf("server encountered errors: %v", errors.Join(errs...))
	// }
	// log.GetLogger(ctx).Info("Server listeners stopped successfully")
	// return nil
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
			go s.handleConnection(ctx, conn)
		}
	}
}

func (s *Server) listenAllUDP(ctx context.Context) error {
	listening := map[string]bool{}
	lock := &sync.Mutex{}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ifaces, err := link.FindSecondaryNetworkInterface(ctx)
		if err != nil {
			return fmt.Errorf("failed to find secondary network interface: %w", err)
		}

		for _, iface := range ifaces {
			log.GetLogger(ctx).Infof("Found interface %s for UDP listening", iface)
			lock.Lock()
			if listening[iface] {
				lock.Unlock()
				log.GetLogger(ctx).Infof("Already listening on interface %s", iface)
				continue
			}
			listening[iface] = true
			lock.Unlock()
			go func(iface string) {
				err := s.listenUDPIface(lctx, iface)
				if err != nil {
					log.GetLogger(ctx).Errorf("Error listening on UDP interface %s: %v", iface, err)
				}
				lock.Lock()
				defer lock.Unlock()
				listening[iface] = false
			}(iface)
		}

		select {
		case <-ctx.Done():
			log.GetLogger(ctx).Info("Stopping all UDP listeners")
			cancel() // Cancel the context to stop all listeners
			return ctx.Err()
		case <-time.After(10 * time.Second):
			log.GetLogger(ctx).Info("Checking for new interfaces to listen on")
			continue
		}
	}
}

func (s *Server) listenUDPIface(ctx context.Context, iface string) error {
	fmt.Println("hi")
	log.GetLogger(ctx).Infof("Listening on UDP for interface %s", iface)
	ifn, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", iface, err)
	}
	if ifn.Flags&net.FlagUp == 0 {
		err = link.SetInterfaceUp(ctx, iface)
		if err != nil {
			return err
		}
	}
	addrs, err := ifn.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface %s: %w", iface, err)
	}
	lanIP := net.IP{}.To4()
	for _, addr := range addrs {
		ip := net.ParseIP(strings.Split(addr.String(), "/")[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		lanIP = ip.To4()
		log.GetLogger(ctx).Infof("Found IP %s for interface %s", lanIP, iface)
		break
	}

	addr := net.JoinHostPort(lanIP.String(), fmt.Sprintf("%d", s.Port))
	uaddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", addr, err)
	}
	listener, err := net.ListenUDP("udp4", uaddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addr, err)
	}
	defer listener.Close()
	log.GetLogger(ctx).Infof("Listening on UDP %s for interface %s", addr, iface)
	return s.runUDPListener(ctx, iface, listener, nil)
}

func (s *Server) runUDPListener(ctx context.Context, iface string, listener *net.UDPConn, buffer []byte) error {
	defer listener.Close()
	if len(buffer) == 0 {
		buffer = make([]byte, 1024)
	}
	log.GetLogger(ctx).Infof("Listening on UDP %s:%d for interface %s", s.IP, s.Port, iface)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		fmt.Println("reading from UDP listener on interface", iface)
		n, addr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			log.GetLogger(ctx).Infof("Error reading from UDP: %v", err)
			continue
		}
		//handle packet
		err = s.handleUDPPacket(ctx, iface, buffer[:n], addr)
		if err != nil {
			log.GetLogger(ctx).Infof("Error handling UDP packet from %s: %v", addr, err)
		}
	}
}

func (s *Server) handleUDPPacket(ctx context.Context, iface string, packet []byte, addr *net.UDPAddr) error {
	if len(packet) < len(UDPIPPayloadPrefix) || !strings.HasPrefix(string(packet[:len(UDPIPPayloadPrefix)]), string(UDPIPPayloadPrefix)) {
		log.GetLogger(ctx).Debugf("Received non-IP packet from %s: %s", addr, packet)
		return nil
	}
	ipBytes := packet[len(UDPIPPayloadPrefix):]
	if len(ipBytes) != IPAddrSize {
		return fmt.Errorf("invalid IP address size in UDP packet from %s: expected %d bytes, got %d", addr, IPAddrSize, len(ipBytes))
	}
	ip := net.IP(ipBytes)
	log.GetLogger(ctx).Debugf("Received IP packet from %s: %s", addr, ip)

	s.udpPingsLock.Lock()
	defer s.udpPingsLock.Unlock()
	s.udpPings[[4]byte(ip)] = udpPing{
		IP:      ip,
		RouteIP: addr.IP,
		Iface:   iface,
		Time:    time.Now(),
	}
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
