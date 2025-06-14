package discover

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mat285/linklan/log"
	"github.com/mat285/linklan/prom"
)

var (
	HeloBytes   = []byte{'H', 'E', 'L', 'L', 'O', '\n'} // HELO message bytes
	AcceptBytes = []byte{'A', 'C', 'E', 'P', 'T', '\n'} // ACCEPT message bytes

	SpeedTestDataSize   int64 = 16 * 1024 * 1024 // 16 MB of data for speed test
	SpeedTestInterval         = 10 * time.Second // Interval for speed test
	SpeedTestBufferSize       = 1024 * 1024      // 1 MB buffer size for speed test

	MetricName = "link_speed" // Metric name for speed tes
)

type Server struct {
	Port int
	IP   string // IP address to bind to, empty for all interfaces

	lock   sync.Mutex
	cancel context.CancelFunc // Cancel function for the server context
	done   chan struct{}      // Channel to signal server done

	peersLock sync.Mutex // Lock for peers slice
	peers     map[byte]map[byte]net.Conn
}

func NewServer(ip string, port int) *Server {
	return &Server{
		IP:    ip,
		Port:  port,
		peers: make(map[byte]map[byte]net.Conn),
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.cancel != nil {
		return fmt.Errorf("server already running")
	}
	s.lock.Lock()
	log.Default().Info("Starting server on", s.IP, ":", s.Port)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // Ensure cancel is called on exit
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.lock.Unlock()
	go s.SearchForPeers(ctx) // Start searching for peers in a separate goroutine
	err := s.Listen(ctx)
	cancel()
	s.lock.Lock()
	s.cancel = nil // Clear cancel function after listen returns
	s.done = nil   // Clear done channel
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
			ip[len(ip)-1] = ipID // Set the last byte to the IP ID
			peer := ip.String()
			peers = append(peers, peer) // Append peer address with port
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
			return ctx.Err() // Exit if context is done
		default:
		}
		err := s.searchWholeLan(ctx, lan) // Search the whole LAN for peers
		if err != nil {
			log.Default().Info("Error searching LAN:", err)
		}
		log.Default().Info("Completed peer search cycle, waiting for next cycle")

		select {
		case <-ctx.Done():
			return ctx.Err() // Exit if context is done
		case <-time.After(60 * time.Second): // Wait for 10 seconds before next search}
		}
	}
}

func (s *Server) searchWholeLan(ctx context.Context, lan byte) error {
	log.Default().Info("Searching whole LAN with ID", lan)
	localIP := net.ParseIP(s.IP)
	localID := localIP[len(localIP)-1] // Get the last byte as local IP ID
	for i := 0; i <= 255; i++ {
		ipID := byte(i) // Use byte type for IP ID
		if ipID == localID {
			continue // Skip local IP ID
		}
		select {
		case <-ctx.Done():
			return ctx.Err() // Exit if context is done
		default:
		}
		s.peersLock.Lock()
		if _, exists := s.peers[ipID]; !exists {
			s.peers[ipID] = make(map[byte]net.Conn) // Initialize peer map if it doesn't exist
		}
		_, exists := s.peers[ipID][lan]
		s.peersLock.Unlock() // Unlock peers map after checking existence

		if !exists {
			log.Default().Info("Trying to ping peer with IP ID", ipID, "and LAN ID", lan)
			err := s.TryPingPeer(ctx, ipID, lan, s.Port)
			if err != nil {
				log.Default().Debug("Failed to ping peer with IP ID", ipID, "and LAN ID", lan, ":", err)
			}
		}
	}
	return nil
}

func (s *Server) Listen(ctx context.Context) error {
	// Placeholder for server listen logic
	// This would typically start a TCP server on s.Port
	listener, err := net.Listen("tcp", net.JoinHostPort(s.IP, fmt.Sprintf("%d", s.Port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err() // Exit if context is done
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			log.Default().Info("Error accepting connection:", err)
		}
		go s.handlePeerConnection(ctx, conn) // Handle each connection in a goroutine
	}
}

func (s *Server) handlePeerConnection(ctx context.Context, conn net.Conn) {
	log.Default().Info("Handling new peer connection from", conn.RemoteAddr())
	intro := make([]byte, len(HeloBytes))
	r, err := conn.Read(intro)
	if err != nil {
		log.Default().Info("Error reading from connection:", err)
		conn.Close() // Close connection on error
		return
	}
	if r != len(HeloBytes) || !bytes.Equal(intro, HeloBytes) {
		log.Default().Info("Invalid HELO message from peer, closing connection")
		conn.Close() // Close connection if HELO message is invalid
		return
	}
	log.Default().Info("Received HELO message from peer, processing connection")
	r, err = conn.Write(AcceptBytes) // Send ACCEPT message to peer
	if err != nil {
		log.Default().Info("Error writing to connection:", err)
		conn.Close() // Close connection on error
		return
	}
	if r != len(AcceptBytes) {
		log.Default().Info("Failed to send ACCEPT message to peer, closing connection")
		conn.Close() // Close connection if ACCEPT message not sent completely
		return
	}

	log.Default().Info("Sent ACCEPT message to peer, processing connection")
	s.peersLock.Lock()

	remoteAddr := addressToIP(conn.RemoteAddr().String()) // Convert remote address to IP
	ipID := remoteAddr[len(remoteAddr)-1]
	lanID := remoteAddr[len(remoteAddr)-2]
	if _, exists := s.peers[ipID]; !exists {
		log.Default().Info("New peer connected:", remoteAddr)
		if len(s.peers[ipID]) == 0 {
			s.peers[ipID] = make(map[byte]net.Conn)
		}
		s.peers[ipID][lanID] = conn // Store connection by local address
	} else if _, exists := s.peers[ipID][lanID]; !exists {
		log.Default().Info("New connection from existing peer:", remoteAddr)
		s.peers[ipID][lanID] = conn // Store new connection
	} else {
		log.Default().Info("Existing peer reconnected:", remoteAddr)
	}
	s.peersLock.Unlock()

	s.runSpeedTest(
		ctx,
		conn,
		nil,
		conn.Read,
	)
}

func (s *Server) Stop() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.cancel != nil {
		s.cancel() // Cancel the server context
		s.cancel = nil
	}
	if s.done != nil {
		close(s.done) // Signal that the server is done
		s.done = nil
	}
	log.Default().Info("Server stopped")
}

func (s *Server) TryPingPeer(ctx context.Context, ipID, lanID byte, port int) error {
	ip := net.ParseIP(s.IP)
	ip[len(ip)-1] = ipID // Set the last byte to the provided value
	log.Default().Debug("Pinging peer at", ip, "on port", port)
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	ip[len(ip)-2] = lanID
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Millisecond)
	if err != nil {
		log.Default().Debug("Failed to connect to", addr, ":", err)
		return err
	}
	r, err := conn.Write(HeloBytes) // Send HELO message
	if err != nil {
		log.Default().Info("Error writing to connection:", err)
		conn.Close() // Close connection on error
		return err
	}
	if r != len(HeloBytes) {
		log.Default().Info("Failed to send HELO message to", addr, ", closing connection")
		conn.Close() // Close connection if HELO message not sent completely
		return fmt.Errorf("failed to send HELO message to %s", addr)
	}
	log.Default().Info("Sent HELO message to", addr, ", waiting for response")
	// Wait for ACCEPT message from peer
	conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond)) // Set read deadline
	acceptBuffer := make([]byte, len(AcceptBytes))
	r, err = conn.Read(acceptBuffer)
	if err != nil {
		conn.Close()
		log.Default().Info("Failed to read ACCEPT message from", addr, ":", err)
		return fmt.Errorf("failed to read ACCEPT message from %s: %w", addr, err)
	}
	if r != len(AcceptBytes) || !bytes.Equal(acceptBuffer, AcceptBytes) {
		conn.Close()
		log.Default().Info("Invalid ACCEPT message from", addr, ", closing connection")
		return fmt.Errorf("invalid ACCEPT message from %s", addr)
	}
	log.Default().Info("Received ACCEPT message from", addr, ", connection established")

	go s.handleClientConnection(ctx, conn) // Handle client connection in a goroutine
	return nil                             // Return nil if connection established successfully
}

func (s *Server) handleClientConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()                            // Ensure connection is closed when done
	ip := addressToIP(conn.RemoteAddr().String()) // Convert remote address to IP
	ipID := ip[len(ip)-1]                         // Get the last byte as IP ID
	lanID := ip[len(ip)-2]                        // Get the second last byte as LAN ID

	s.peersLock.Lock()
	if s.peers[ipID] == nil {
		s.peers[ipID] = make(map[byte]net.Conn) // Initialize peer map if it doesn't exist
	}
	// Initialize peer map if it doesn't exist
	s.peers[ipID][lanID] = conn // Store connection by local address
	s.peersLock.Unlock()

	defer func() {
		s.peersLock.Lock()
		delete(s.peers[ipID], lanID) // Remove connection from peers map
		if len(s.peers[ipID]) == 0 {
			delete(s.peers, ipID) // Remove IP ID from peers map if no connections left
		}
		s.peersLock.Unlock()
	}()

	log.Default().Info("Handling client connection from", conn.RemoteAddr())
	s.runSpeedTest(
		ctx,
		conn,
		rand.Read, // Pre function to fill buffer with random data
		conn.Write,
	)
}

func (s *Server) runSpeedTest(ctx context.Context, conn net.Conn, pre func([]byte) (int, error), move func([]byte) (int, error)) {
	localIP := net.ParseIP(s.IP)
	localIP[len(localIP)-2] = 1                    // Set the second last byte to 1 for local IP
	ip := addressToIP(conn.RemoteAddr().String())  // Convert remote address to IP
	rIP := addressToIP(conn.RemoteAddr().String()) // Get local address IP
	rIP[len(rIP)-2] = 1                            // Set the second last byte to 1 for remote IP
	buffer := make([]byte, SpeedTestBufferSize)    // Buffer for speed test
	if pre != nil {
		_, err := pre(buffer) // Call pre function if provided
		if err != nil {
			log.Default().Info("Error in pre function:", err)
			return
		}
	}

	sent := int64(0) // Track bytes sent
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := move(buffer)
		if err != nil {
			log.Default().Info("Error writing to client:", err)
			return
		}
		sent += int64(n)
		if sent >= SpeedTestDataSize { // If 1 MB sent
			speed, mb := calculateSpeed(sent, start) // Calculate speed
			log.Default().Infof("Calculated speed of connection with %s: %f Gbps with %d MB of data", ip.String(), speed, mb)
			err = prom.AppendMetric(MetricName, fmt.Sprintf("%0.4f", speed), map[string]string{
				"host":   localIP.String(),
				"remote": rIP.String(),
			})
			if err != nil {
				log.Default().Info("Error appending metric:", err)
			}
			select {
			case <-ctx.Done():
				log.Default().Info("Context done, stopping client connection handling")
				return // Exit if context is done
			case <-time.After(SpeedTestInterval): // Wait for 5 seconds before next send
				log.Default().Info("Waiting for next send to client")
			}

			sent = 0 // Reset sent count
			if pre != nil {
				pre(buffer) // Fill buffer with new random data
			}
			start = time.Now() // Reset start time
		}
	}
}

func calculateSpeed(sent int64, start time.Time) (float64, int64) {
	elapsed := time.Since(start) / time.Nanosecond
	sent = sent * 8                    // Convert bytes to bits
	sentMB := sent / (8 * 1024 * 1024) // Convert bits to MB
	if elapsed == 0 {
		return 0, sentMB // Avoid division by zero
	}
	speed := (float64(sent) / float64(elapsed))
	return speed, sentMB
}

func addressToIP(addr string) net.IP {
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return ip
}
