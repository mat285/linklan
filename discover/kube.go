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
	return PingAllInterfaces(ctx, nodes, 16443)
}
