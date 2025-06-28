package link

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mat285/linklan/log"
)

const (
	NetworkDeviceDirectory = "/sys/class/net"

	InterfaceSyncInterval = 500 * time.Millisecond

	ModeUnknown EventMode = 0 // Unknown mode
	ModeCreate  EventMode = 1
	ModeRemove  EventMode = 2
)

type EventMode int

type NotifyFunc func(ctx context.Context, iface net.Interface, mode EventMode) error

type DeviceWatcher struct {
	lock   sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	ifacesLock sync.Mutex               // Lock for ifaces map
	ifaces     map[string]net.Interface // Track known interfaces

	Notify NotifyFunc
}

func NewDeviceWatcher(notify NotifyFunc) *DeviceWatcher {
	return &DeviceWatcher{
		lock:       sync.Mutex{},
		cancel:     nil,
		done:       nil,
		ifacesLock: sync.Mutex{},
		ifaces:     make(map[string]net.Interface),
		Notify:     notify,
	}
}

func (dw *DeviceWatcher) Start(ctx context.Context) error {
	if dw.cancel != nil {
		return fmt.Errorf("already runnning") // Already initialized
	}

	dw.lock.Lock()
	if dw.cancel != nil {
		dw.lock.Unlock()
		return fmt.Errorf("already runnning") // Already initialized
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dw.cancel = cancel
	dw.done = make(chan struct{})
	dw.lock.Unlock()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	err = watcher.Add(NetworkDeviceDirectory)
	if err != nil {
		return err
	}

	err = dw.watchDeviceChanges(ctx, watcher)
	dw.lock.Lock()
	dw.cancel = nil
	close(dw.done)
	dw.done = nil
	dw.lock.Unlock()
	return err
}

func (dw *DeviceWatcher) watchDeviceChanges(ctx context.Context, watcher *fsnotify.Watcher) error {
	if watcher == nil {
		return fmt.Errorf("device watcher is not initialized")
	}
	log.GetLogger(ctx).Info("Starting device watcher for network interfaces...")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := dw.RefreshInterfaces(ctx)
		if err != nil {
			log.GetLogger(ctx).Errorf("Error refreshing interfaces: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(InterfaceSyncInterval):
			continue
		}
	}
}

func (dw *DeviceWatcher) RefreshInterfaces(ctx context.Context) error {
	dw.ifacesLock.Lock()
	defer dw.ifacesLock.Unlock()

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %w", err)
	}

	currentIfaces := make(map[string]net.Interface)
	for _, iface := range ifaces {
		currentIfaces[iface.Name] = iface
		if _, exists := dw.ifaces[iface.Name]; !exists {
			log.GetLogger(ctx).Info("Adding device:", iface.Name)
			if err := dw.notify(ctx, iface, ModeCreate); err != nil {
				log.GetLogger(ctx).Error("Error adding device:", iface.Name, err)
				continue
			}
		}
	}

	for name := range dw.ifaces {
		if iface, exists := currentIfaces[name]; !exists {
			log.GetLogger(ctx).Info("Removing device:", name)
			if err := dw.notify(ctx, iface, ModeRemove); err != nil {
				log.GetLogger(ctx).Error("Error removing device:", name, err)
				// currentIfaces[name] = iface // Keep it in currentIfaces to avoid nil dereference
				continue
			}
		}
	}

	dw.ifaces = currentIfaces
	return nil
}

func (dw *DeviceWatcher) GetInterfaces() []net.Interface {
	dw.ifacesLock.Lock()
	defer dw.ifacesLock.Unlock()

	ifaces := make([]net.Interface, 0, len(dw.ifaces))
	for _, iface := range dw.ifaces {
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func (dw *DeviceWatcher) notify(ctx context.Context, iface net.Interface, mode EventMode) error {
	if dw.Notify == nil {
		return nil
	}
	return dw.Notify(ctx, iface, mode)
}

func (dw *DeviceWatcher) Stop() error {
	cancel := dw.cancel
	if cancel != nil {
		cancel()
	}
	done := dw.done
	if done != nil {
		<-done
	}
	return nil
}
