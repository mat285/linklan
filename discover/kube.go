package discover

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/mat285/linklan/link"
)

var isIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

type KubeAddress struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

func GetKubeNodeIPs(ctx context.Context) ([]string, error) {
	fmt.Println("Fetching Kubernetes node IPs...")
	output, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses[*].address}'").CombinedOutput()
	if err != nil {
		fmt.Println("Error executing kubectl command:", string(output))
		return nil, err
	}
	addrs := strings.Split(string(output), " ")
	var ips []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if !isIP.MatchString(addr) {
			continue
		}
		ips = append(ips, addr)
	}
	return ips, nil
}

func GetActiveKubePeers(ctx context.Context, localIP string) ([]string, error) {
	ips, err := GetKubeNodeIPs(ctx)
	if err != nil {
		return nil, err
	}
	fmt.Println("Checking for active peers from", ips)
	filteredIPs := []string{}
	for _, ip := range ips {
		if ip == localIP {
			continue
		}
		err := TCPPing(ctx, link.SecondaryIPFromPrimaryIP(ip), 16443)
		if err == nil {
			filteredIPs = append(filteredIPs, ip)
		}
	}
	fmt.Println("Active peers found:", filteredIPs)
	return filteredIPs, nil
}
