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
	"sort"
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

	DialTimeout = 10 * time.Millisecond

	SpeedTestDataSize   int64 = 16 * 1024 * 1024
	SpeedTestInterval         = 60 * time.Second
	SpeedTestBufferSize       = 1024 * 1024

	PingInterval = 1 * time.Second
	PingTimeout  = 3 * time.Second

	MetricName = "link_speed"
)

type Server struct {
	Port    int
	LocalIP string
	IP      string

	lock   sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	peersLock sync.Mutex
	peers     map[string]map[[4]byte]net.Conn

	knownPeersLock sync.Mutex
	knownPeers     map[string]struct{} // Track known peers to avoid duplicates
}

func NewServer(localIP, listenIP string, port int) *Server {
	return &Server{
		LocalIP:        localIP,
		IP:             listenIP,
		Port:           port,
		peers:          make(map[string]map[[4]byte]net.Conn),
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

func (s *Server) ActivePeers(ctx context.Context) map[string][]string {
	localIP, _, err := net.ParseCIDR(config.GetConfig(ctx).Lan.CIDR)
	if err != nil {
		log.GetLogger(context.Background()).Errorf("Failed to parse local CIDR: %v", err)
		return nil
	}
	localIP = localIP.To4()

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	peerMap := make(map[string][]string)
	for iface, pps := range s.peers {
		peers := make([]string, 0, len(s.peers))
		for ip := range pps {
			peer := make(net.IP, len(localIP))
			copy(peer, localIP)
			peer[len(peer)-1] = ip[len(ip)-1] // Use the last byte of local IP for the peer
			peers = append(peers, peer.String())
		}
		sort.Strings(peers)
		peerMap[iface] = peers
	}
	return peerMap
}

func (s *Server) SearchForPeers(ctx context.Context) error {
	// lan := byte(0)
	log.GetLogger(ctx).Info("Starting peer search on LAN")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// lan := byte(0)
		// max := byte(1)
		// // if numIfaces, err := link.FindSecondaryNetworkInterface(ctx); err == nil {
		// // 	max = byte(len(numIfaces))
		// // }

		// ifaces, err := link.FindSecondaryNetworkInterface(ctx)
		// if err != nil {
		// 	log.GetLogger(ctx).Errorf("Failed to find secondary network interfaces: %v", err)
		// 	return err
		// }
		// log.GetLogger(ctx).Infof("Found %d secondary network interfaces", len(ifaces))
		// for _, iface := range ifaces {
		// 	select {
		// 	case <-ctx.Done():
		// 		log.GetLogger(ctx).Info("Stopping peer search due to context cancellation")
		// 		return ctx.Err()
		// 	default:
		// 	}
		// 	log.GetLogger(ctx).Info("Searching for peers on interface", iface)
		// 	err := s.searchInterface(ctx, iface)
		// 	if err != nil {
		// 		log.GetLogger(ctx).Info("Error searching interface:", err)
		// 	}
		// }
		// for lan < max {
		// 	select {
		// 	case <-ctx.Done():
		// 		log.GetLogger(ctx).Info("Stopping peer search due to context cancellation")
		// 		return ctx.Err()
		// 	default:
		// 	}
		// 	log.GetLogger(ctx).Info("Searching for peers on LAN ID", lan)
		// 	err := s.searchWholeLan(ctx, lan)
		// 	if err != nil {
		// 		log.GetLogger(ctx).Info("Error searching LAN:", err)
		// 	}
		// 	lan++
		// }
		// log.GetLogger(ctx).Info("Completed peer search cycle, waiting for next cycle")

		err := s.searchBySearchIP(ctx)
		if err != nil {
			log.GetLogger(ctx).Errorf("Error searching by search IP: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(rand.Intn(2500)+60000) * time.Millisecond):
		}
	}
}

func (s *Server) searchInterface(ctx context.Context, iface string) error {
	log.GetLogger(ctx).Infof("Searching for peers on interface %s", iface)
	localIP := net.ParseIP(s.LocalIP).To4()
	if localIP == nil {
		err := fmt.Errorf("invalid local IP %s", s.LocalIP)
		log.GetLogger(ctx).Errorf("Failed to parse local IP %s: %v", s.LocalIP, err)
		return fmt.Errorf("failed to parse local IP %s: %w", s.LocalIP, err)
	}
	err := link.SetupSearchRoutes(ctx, iface, localIP)
	if err != nil {
		log.GetLogger(ctx).Errorf("Failed to setup search routes for interface %s: %v", iface, err)
		return err
	}

	log.GetLogger(ctx).Infof("Searching LAN IPs for peers on interface %s", iface)
	err = s.searchLanIPForPeers(ctx, iface, localIP[len(localIP)-1], net.IP(link.SearchCidr[:]))
	if err != nil {
		log.GetLogger(ctx).Errorf("Failed to search LAN IP for peers on interface %s: %v", iface, err)
	}

	log.GetLogger(ctx).Infof("Tearing down search routes for interface %s", iface)
	if err := link.TearDownSearchRoutes(ctx, iface); err != nil {
		log.GetLogger(ctx).Errorf("Failed to tear down search routes for interface %s: %v", iface, err)
		return err
	}
	return nil
}

func (s *Server) searchBySearchIP(ctx context.Context) error {
	log.GetLogger(ctx).Info("Searching with search IPs")
	localIP := net.ParseIP(s.LocalIP).To4()
	if localIP == nil {
		err := fmt.Errorf("invalid local IP %s", s.LocalIP)
		log.GetLogger(ctx).Errorf("Failed to parse local IP %s: %v", s.LocalIP, err)
		return fmt.Errorf("failed to parse local IP %s: %w", s.LocalIP, err)
	}
	ifaces, err := link.FindSecondaryNetworkInterface(ctx)
	if err != nil {
		log.GetLogger(ctx).Errorf("Failed to find secondary network interfaces: %v", err)
		return err
	}
	for _, iface := range ifaces {
		log.GetLogger(ctx).Infof("Searching with interface %s", iface)
		err = link.SetupSearchRoutes(ctx, iface, net.ParseIP(s.LocalIP))
		if err != nil {
			log.GetLogger(ctx).Errorf("Failed to setup search routes for interface %s: %v", iface, err)
			continue
		}

		log.GetLogger(ctx).Infof("Searching LAN IPs for peers on interface %s", iface)
		err = s.searchLanIPForPeers(ctx, iface, localIP[len(localIP)-1], net.IP(link.SearchCidr[:]))
		if err != nil {
			log.GetLogger(ctx).Errorf("Failed to search LAN IP for peers on interface %s: %v", iface, err)
		}

		log.GetLogger(ctx).Infof("Tearing down search routes for interface %s", iface)
		if err := link.TearDownSearchRoutes(ctx, iface); err != nil {
			log.GetLogger(ctx).Errorf("Failed to tear down search routes for interface %s: %v", iface, err)
			return err
		}
	}
	log.GetLogger(ctx).Info("Search with search IPs completed")
	return nil
}

func (s *Server) searchWholeLan(ctx context.Context, iface string, lan byte) error {
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
	return s.searchLanIPForPeers(ctx, iface, localID, pingIP)
}

func (s *Server) searchLanIPForPeers(ctx context.Context, iface string, localID byte, pingIP net.IP) error {
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
		_, exists := s.peers[iface][[4]byte(pingIP)]
		s.peersLock.Unlock()

		if !exists {
			pingIP[len(pingIP)-1] = byte(i)
			log.GetLogger(ctx).Debugf("Trying to ping peer with IP %s", pingIP)
			err := s.tryPingPeer(ctx, iface, pingIP, s.Port)
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
		go s.handleConnection(ctx, "", link.WrapConn(conn))
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

func (s *Server) tryPingPeer(ctx context.Context, iface string, ip net.IP, port int) error {
	log.GetLogger(ctx).Debug("Pinging peer at", ip, "on port", port)
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp4", addr, DialTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	lc := link.WrapConn(conn)
	go s.handleConnection(ctx, iface, lc)
	return nil
}

func (s *Server) tryReconnect(ctx context.Context, iface string, ip net.IP) error {
	log.GetLogger(ctx).Info("Attempting to reconnect to peer with IP ID", ip)
	maxAttempts := 1
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(mrand.Intn(500))*time.Millisecond + time.Duration(1000)*time.Millisecond):
		}

		s.lock.Lock()
		_, exists := s.peers[iface][[4]byte(ip)]
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
			go s.handleConnection(ctx, iface, lc)
			return nil
		}
		log.GetLogger(ctx).Debugf("Failed to reconnect to peer at %s: %v", addr, err)
	}
	return fmt.Errorf("failed to reconnect to peer with IP %s after %d attempts", ip, maxAttempts)
}

func (s *Server) handleConnection(ctx context.Context, iface string, conn *link.Conn) {
	defer conn.Close()
	if iface == "" {
		localIP := addressToIP(conn.LocalAddr().String())
		ifaces, err := link.FindSecondaryNetworkInterface(ctx)
		if err != nil {
			log.GetLogger(ctx).Errorf("Failed to find secondary network interfaces: %v", err)
			return
		}
		if len(ifaces) == 0 {
			log.GetLogger(ctx).Error("No secondary network interfaces found, cannot handle connection")
			return
		}
		for _, ifc := range ifaces {
			interfc, err := net.InterfaceByName(ifc)
			if err != nil {
				log.GetLogger(ctx).Errorf("Failed to get interface %s: %v", ifc, err)
				continue
			}
			addrs, err := interfc.Addrs()
			if err != nil {
				log.GetLogger(ctx).Errorf("Failed to get addresses for interface %s: %v", ifc, err)
				continue
			}
			for _, addr := range addrs {
				if strings.Contains(addr.String(), localIP.String()) {
					iface = ifc
					log.GetLogger(ctx).Debugf("Using interface %s for connection from %s", iface, localIP)
					break
				}
			}
			if iface != "" {
				break
			}
		}
	}
	ip := addressToIP(conn.RemoteAddr().String())
	log.GetLogger(ctx).Debugf("Handling connection from %s", ip)
	if !s.addNewConn(ctx, iface, conn) {
		log.GetLogger(ctx).Infof("Connection from %s already exists, closing new connection", ip)
		return
	}
	defer s.cleanupConn(ctx, iface, conn)
	defer func() { go s.tryReconnect(ctx, iface, ip) }() // Attempt to reconnect if the connection is closed unexpectedly
	s.handleConnRW(ctx, conn)
}

func (s *Server) addNewConn(ctx context.Context, iface string, conn *link.Conn) bool {
	ip := addressToIP(conn.RemoteAddr().String())

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.knownPeersLock.Lock()
	defer s.knownPeersLock.Unlock()
	s.knownPeers[ip.String()] = struct{}{}

	if _, exists := s.peers[iface][[4]byte(ip)]; exists {
		log.GetLogger(ctx).Infof("Connection from %s already exists, closing older connection", ip)
		return false
	}
	log.GetLogger(ctx).Infof("Adding new peer connection from %s", ip)
	s.peers[iface][[4]byte(ip)] = conn
	return true
}

func (s *Server) cleanupConn(ctx context.Context, iface string, conn *link.Conn) {
	ip := [4]byte(addressToIP(conn.RemoteAddr().String()))

	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	if s.peers[iface][ip] != conn {
		return
	}
	log.GetLogger(ctx).Infof("Removing closed peer connection from %s", ip)
	delete(s.peers[iface], ip)
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
