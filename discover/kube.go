package discover

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

var isIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

type KubeAddress struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

func GetKubeNodeIPs(ctx context.Context) ([]string, error) {
	log.GetLogger(ctx).Info("Fetching Kubernetes node IPs...")
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses[*].address}'")
	cmd.Env = append(cmd.Env, "KUBECONFIG=/home/michael/.kube/config")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.GetLogger(ctx).Info("Error executing kubectl command:", string(output))
		return nil, err
	}
	addrs := strings.Split(strings.Trim(string(output), "'"), " ")
	var ips []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if !strings.HasPrefix(addr, link.PrimaryLanIpPrefix) {
			continue
		}
		ips = append(ips, addr)
	}
	return ips, nil
}

func GetActiveKubePeers(ctx context.Context, localIP string) (map[string][]string, error) {
	ips, err := GetKubeNodeIPs(ctx)
	if err != nil {
		return nil, err
	}
	log.GetLogger(ctx).Info("Checking for active peers from", ips)
	nodes := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == localIP {
			continue
		}
		parsed := net.ParseIP(ip).To4()
		if parsed == nil {
			log.GetLogger(ctx).Info("Skipping invalid IP:", ip)
			continue
		}
		nodes = append(nodes, parsed)
	}
	if len(nodes) == 0 {
		log.GetLogger(ctx).Info("No valid IPs found to ping")
		return nil, nil
	}
	peers, err := PingAllInterfaces(ctx, nodes, 16443)
	if err != nil {
		log.GetLogger(ctx).Error("Failed to ping interfaces:", err)
		return nil, err
	}
	ifaces := make([]string, 0, len(peers))
	seen := make(map[string]bool)
	for iface := range peers {
		ifaces = append(ifaces, iface)
	}
	ifaces, err = link.SortInterfacesBySpeed(ifaces)
	if err != nil {
		log.GetLogger(ctx).Error("Failed to sort interfaces by speed:", err)
		return nil, err
	}
	activePeers := make(map[string][]string)
	for _, iface := range ifaces {
		if _, ok := peers[iface]; !ok {
			log.GetLogger(ctx).Info("No active peers found on interface:", iface)
			continue
		}
		activePeers[iface] = make([]string, 0, len(peers[iface]))
		for _, peer := range peers[iface] {
			if !seen[peer] {
				seen[peer] = true
				activePeers[iface] = append(activePeers[iface], peer)
			}
		}
	}
	log.GetLogger(ctx).Info("Active peers found:", activePeers)
	if len(activePeers) == 0 {
		log.GetLogger(ctx).Info("No active peers found")
		return nil, nil
	}
	return activePeers, nil
}
