package discover

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

func PingAllInterfaces(ctx context.Context, nodes []net.IP, port int) (map[string][]string, error) {
	ifaceNames, err := link.FindSecondaryNetworkInterface(ctx)
	if err != nil {
		log.GetLogger(ctx).Error("Failed to get network interfaces:", err)
		return nil, err
	}

	peers := make(map[string][]string)

	for _, name := range ifaceNames {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.GetLogger(ctx).Error("Failed to get interface by name", name, ":", err)
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}
		found, err := PingInterface(ctx, *iface, nodes, port)
		if err != nil {
			log.GetLogger(ctx).Error("Failed to ping interface", iface.Name, ":", err)
			continue
		}
		if len(found) > 0 {
			log.GetLogger(ctx).Info("Found active peers on interface", iface.Name, ":", found)
			peers[iface.Name] = found
		} else {
			log.GetLogger(ctx).Info("No active peers found on interface", iface.Name)
		}
	}

	return peers, nil
}

func PingInterface(ctx context.Context, iface net.Interface, ips []net.IP, port int) ([]string, error) {
	if err := link.SetupSearch(ctx, iface.Name); err != nil {
		log.GetLogger(ctx).Error("Failed to setup search route for interface", iface.Name, ":", err)
		return nil, err
	}
	filteredIPs := []string{}
	lock := new(sync.Mutex)
	wg := new(sync.WaitGroup)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			ping := make(net.IP, len(link.SearchCidr))
			copy(ping, link.SearchCidr[:])
			ping[len(ping)-1] = ip[len(ip)-1] // Use last octet of IP for ping
			log.GetLogger(ctx).Info("Pinging IP:", ping, "on port:", port)
			err := TCPPing(ctx, ping.String(), port)
			if err != nil {
				log.GetLogger(ctx).Info("Ping failed for IP:", ip, "Error:", err)
				return
			}
			log.GetLogger(ctx).Info("Ping successful for IP:", ip)
			lock.Lock()
			filteredIPs = append(filteredIPs, ip.String())
			lock.Unlock()
		}(ip)
	}
	wg.Wait()
	log.GetLogger(ctx).Info("Active peers found:", filteredIPs)
	return filteredIPs, nil
}

func TCPPing(ctx context.Context, ip string, port int) error {
	log.GetLogger(ctx).Info("Pinging IP:", ip, "on port:", port)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Millisecond)
	if err != nil {
		log.GetLogger(ctx).Info("Failed to connect to", addr, ":", err)
		return err
	}
	conn.Close()
	log.GetLogger(ctx).Info("Successfully connected to", addr)
	return nil
}
