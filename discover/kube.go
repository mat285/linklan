package discover

import (
	"context"
	"os/exec"
	"strings"

	"github.com/mat285/linklan/link"
	"github.com/mat285/linklan/log"
)

// import (
// 	"context"
// 	"os/exec"
// 	"regexp"
// 	"strings"
// 	"sync"

// 	"github.com/mat285/linklan/link"
// 	"github.com/mat285/linklan/log"
// )

// var isIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// type KubeAddress struct {
// 	Address string `json:"address"`
// 	Type    string `json:"type"`
// }

// func GetKubeNodeIPs(ctx context.Context) ([]string, error) {
// 	log.GetLogger(ctx).Info("Fetching Kubernetes node IPs...")
// 	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses[*].address}'")
// 	cmd.Env = append(cmd.Env, "KUBECONFIG=/home/michael/.kube/config")
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		log.GetLogger(ctx).Info("Error executing kubectl command:", string(output))
// 		return nil, err
// 	}
// 	addrs := strings.Split(strings.Trim(string(output), "'"), " ")
// 	var ips []string
// 	for _, addr := range addrs {
// 		addr = strings.TrimSpace(addr)
// 		if !strings.HasPrefix(addr, link.PrimaryLanIpPrefix) {
// 			continue
// 		}
// 		ips = append(ips, addr)
// 	}
// 	return ips, nil
// }

// func GetActiveKubePeers(ctx context.Context, localIP string) ([]string, error) {
// 	ips, err := GetKubeNodeIPs(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	log.GetLogger(ctx).Info("Checking for active peers from", ips)
// 	filteredIPs := []string{}
// 	lock := new(sync.Mutex)
// 	wg := new(sync.WaitGroup)
// 	for _, ip := range ips {
// 		if ip == localIP {
// 			continue
// 		}
// 		wg.Add(1)
// 		go func(ip string) {
// 			defer wg.Done()
// 			err := TCPPing(ctx, link.SecondaryIPFromPrimaryIP(ip, 0), 16443)
// 			if err == nil {
// 				lock.Lock()
// 				filteredIPs = append(filteredIPs, ip)
// 				lock.Unlock()
// 			}
// 		}(ip)
// 	}
// 	wg.Wait()
// 	log.GetLogger(ctx).Info("Active peers found:", filteredIPs)
// 	return filteredIPs, nil
// }

type KubeNode struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func GetKubeNodes(ctx context.Context) (map[string]string, error) {
	log.GetLogger(ctx).Info("Fetching Kubernetes node IPs...")
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "jsonpath='{.items[*].status.addresses[*].address}'")
	cmd.Env = append(cmd.Env, "KUBECONFIG=/home/michael/.kube/config")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.GetLogger(ctx).Info("Error executing kubectl command:", string(output))
		return nil, err
	}
	addrs := strings.Split(strings.Trim(string(output), "'"), " ")
	nodes := make(map[string]string)
	for i := 0; i < len(addrs); i += 2 {
		if !strings.HasPrefix(addrs[i], link.PrimaryLanIpPrefix) {
			continue
		}
		nodes[addrs[i+1]] = addrs[i]
	}
	return nodes, nil
}
