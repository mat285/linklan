package discover

import (
	"context"
	"net"
)

func TCPPing(ctx context.Context, ip string, port int) error {
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
