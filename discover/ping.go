package discover

import (
	"context"
	"fmt"
	"net"
	"time"
)

func TCPPing(ctx context.Context, ip string, port int) error {
	fmt.Println("Pinging IP:", ip, "on port:", port)
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ip, port), time.Second*5)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
