package discover

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

var isIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

type KubeAddress struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

func GetKubeNodeIPs(ctx context.Context) ([]string, error) {
	log.Default().Info("Fetching Kubernetes node IPs...")
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses[*].address}'")
	cmd.Env = append(cmd.Env, "KUBECONFIG=/home/michael/.kube/config")
	output, err := cmd.CombinedOutput()
	fmt.Println("Command output:", string(output))
	if err != nil {
		log.Default().Info("Error executing kubectl command:", string(output))
		return nil, err
	}
	addrs := strings.Split(string(output), " ")
	var ips []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		fmt.Println("Processing address:", addr)
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
	log.Default().Info("Checking for active peers from", ips)
	filteredIPs := []string{}
	lock := new(sync.Mutex)
	wg := new(sync.WaitGroup)
	for _, ip := range ips {
		if ip == localIP {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			err := TCPPing(ctx, link.SecondaryIPFromPrimaryIP(ip), 16443)
			if err == nil {
				lock.Lock()
				filteredIPs = append(filteredIPs, ip)
				lock.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	log.Default().Info("Active peers found:", filteredIPs)
	return filteredIPs, nil
}
