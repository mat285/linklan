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
	output, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses}'").CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return nil, err
	}
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
