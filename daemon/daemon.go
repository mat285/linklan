package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mat285/linklan/discover"
	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

const (
	MaxInitAttempts = 10
	InitRetryDelay  = 5 * time.Second
	SyncInterval    = 30 * time.Second
)

type Daemon struct {
	lock   sync.Mutex
	cancel context.CancelFunc

	Log *log.Logger

	LocalIP string
	Peers   []string
}

func New() *Daemon {
	return &Daemon{
		Log: log.New(),
	}
}

func (d *Daemon) Start(ctx context.Context) error {
	if err := d.init(ctx); err != nil {
		return fmt.Errorf("failed to initialize daemon: %w", err)
	}
	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()
	d.lock.Lock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.cancel = cancel
	d.lock.Unlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.runSync(ctx); err != nil {
				d.Log.Info("Error during sync:", err)
			}
		}
	}
}

func (d *Daemon) Stop() {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	d.LocalIP = ""
	d.Peers = nil
}

func (d *Daemon) init(ctx context.Context) error {
	d.Log.Info("Initializing daemon: ensuring direct LAN connection and discovering peers")
	d.lock.Lock()
	defer d.lock.Unlock()
	attempts := 0
	for attempts < MaxInitAttempts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ip, err := link.FindPrimaryNetworkIP(ctx)
		if err == nil {
			d.LocalIP = ip
			d.Log.Info("Daemon initialized with primary network IP:", d.LocalIP)
			return nil
		}
		d.Log.Info("Attempt", attempts+1, "to find primary network IP failed:", err)
		if attempts < MaxInitAttempts {
			attempts++
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(InitRetryDelay):
			}
		}
	}
	return fmt.Errorf("failed to find primary network IP after %d attempts", MaxInitAttempts)
}

func (d *Daemon) runSync(ctx context.Context) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.Log.Info("Running sync: ensuring direct LAN connection and discovering peers")
	err := link.EnsureDirectLan(ctx, d.Peers)
	if err != nil {
		return err
	}
	peers, err := discover.GetActiveKubePeers(ctx, d.LocalIP)
	if err != nil {
		return err
	}
	d.Peers = peers
	return link.EnsureDirectLan(ctx, peers)
}
