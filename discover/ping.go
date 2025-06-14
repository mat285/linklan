package discover

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mat285/linklan/log"
)

func TCPPing(ctx context.Context, ip string, port int) error {
	log.Default().Info("Pinging IP:", ip, "on port:", port)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Millisecond)
	if err != nil {
		log.Default().Info("Failed to connect to", addr, ":", err)
		return err
	}
	conn.Close()
	log.Default().Info("Successfully connected to", addr)
	return nil
}
