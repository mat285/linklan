package daemon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/mat285/linklan/discover"
	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

const (
	MaxInitAttempts  = 10
	InitRetryDelay   = 5 * time.Second
	SyncInterval     = 10 * time.Second
	PeerSyncInterval = 2 * time.Second
)

type Daemon struct {
	lock   sync.Mutex
	cancel context.CancelFunc

	lastSync time.Time

	Log *log.Logger

	LocalIP string
	Peers   []string

	Watcher *link.DeviceWatcher

	Server *discover.Server
}

func New() *Daemon {
	d := &Daemon{
		Log: log.New(),
	}
	d.Watcher = link.NewDeviceWatcher(d.onInterfaceChange)
	return d
}

func (d *Daemon) Start(ctx context.Context) error {
	if err := d.init(ctx); err != nil {
		return fmt.Errorf("failed to initialize daemon: %w", err)
	}
	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()
	peerTicker := time.NewTicker(SyncInterval)
	defer peerTicker.Stop()
	d.lock.Lock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.cancel = cancel
	d.Server = discover.NewServer(link.SecondaryIPFromPrimaryIP(d.LocalIP), 11221)
	d.lock.Unlock()
	go d.Watcher.Start(ctx)
	defer d.Watcher.Stop()
	go func() {
		if err := d.Server.Start(ctx); err != nil {
			d.Log.Info("Server stopped with error:", err)
			d.lock.Lock()
			defer d.lock.Unlock()
			if d.cancel != nil {
				d.cancel()
				d.cancel = nil
			}
		}
	}()
	defer d.Server.Stop()

	// initial sync before starting the ticker
	if err := d.runSync(ctx); err != nil {
		d.Log.Info("Error during sync:", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.runSync(ctx); err != nil {
				d.Log.Info("Error during sync:", err)
			}
		case <-peerTicker.C:
			if _, err := d.syncPeers(ctx); err != nil {
				d.Log.Info("Error during peer sync:", err)
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
	if d.lastSync.Add(SyncInterval).After(time.Now()) {
		d.Log.Info("Skipping sync, last sync was too recent")
		return nil
	}
	synced, err := d.syncPeers(ctx)
	if err != nil {
		return fmt.Errorf("failed to sync peers: %w", err)
	}
	if synced {
		return nil
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.ensureLanUnsafe(ctx)
}

func (d *Daemon) ensureLanUnsafe(ctx context.Context) error {
	peers := d.Peers
	log.Default().Info("Ensuring direct LAN connection with peers:", peers)
	err := link.EnsureDirectLan(ctx, peers)
	if err != nil {
		return fmt.Errorf("failed to ensure direct LAN connection: %w", err)
	}
	d.Log.Info("Direct LAN connection established successfully")
	d.lastSync = time.Now()
	return nil
}

func (d *Daemon) syncPeers(ctx context.Context) (bool, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.Log.Info("Running peer sync")
	d.Log.Info("Current Peers:", d.Peers)
	peers, err := discover.GetActiveKubePeers(ctx, d.LocalIP)
	if err != nil {
		return false, err
	}
	sort.Strings(peers)

	needsSync := len(peers) != len(d.Peers)
	if !needsSync {
		sort.Strings(peers)
		for i, peer := range peers {
			if d.Peers[i] != peer {
				needsSync = true
				break
			}
		}
	}
	d.Peers = peers

	if !needsSync {
		d.Log.Info("No peer changes detected, skipping LAN setup")
		return false, nil
	}
	d.Log.Info("Peer changes detected, re-syncing LAN setup")
	return true, d.ensureLanUnsafe(ctx)
}

func (d *Daemon) onInterfaceChange(ctx context.Context, iface net.Interface, mode link.EventMode) error {
	log.Default().Info("Interface change detected:", iface.Name, "Mode:", mode)
	if mode != link.ModeCreate {
		log.Default().Info("Skipping interface", iface.Name, "for mode", mode)
		return nil
	}

	valid, _, err := link.IsSecondaryNetworkInterface(iface)
	if err != nil {
		return fmt.Errorf("failed to check if interface %s is a secondary network interface: %w", iface.Name, err)
	}
	if !valid {
		log.Default().Info("Interface", iface.Name, "is not a secondary network interface, skipping")
		return nil
	}
	return d.ensureLanUnsafe(ctx)
}
