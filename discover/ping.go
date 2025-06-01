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
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ip, port), time.Second*5)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
