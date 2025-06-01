package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/mat285/linklan/link"
)

type KubeAddress struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

func GetKubeNodeIPs(ctx context.Context) ([]string, error) {
	fmt.Println("Fetching Kubernetes node IPs...")
	output, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses}'").CombinedOutput()
	if err != nil {
		fmt.Println("Error executing kubectl command:", string(output))
		return nil, err
	}
	output = output[1 : len(output)-1]
	fmt.Println("Raw output from kubectl:", string(output))
	var addresses []KubeAddress
	err = json.Unmarshal(output, &addresses)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, addr := range addresses {
		if addr.Type == "InternalIP" {
			ips = append(ips, addr.Address)
		}
	}
	return ips, nil
}

func GetActiveKubePeers(ctx context.Context, localIP string) ([]string, error) {
	ips, err := GetKubeNodeIPs(ctx)
	if err != nil {
		return nil, err
	}
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
	return filteredIPs, nil
}
