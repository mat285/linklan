package link

import (
	"net"
	"sync"
)

type Conn struct {
	open bool
	lock sync.Mutex
	net.Conn
}

func WrapConn(c net.Conn) *Conn {
	return &Conn{
		open: true,
		Conn: c,
	}
}

func (c *Conn) IsOpen() bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.open
}

func (c *Conn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.open {
		return nil
	}
	if c.Conn != nil {
		c.open = false
		return c.Conn.Close()
	}
	return nil
}
