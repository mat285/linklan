package link

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const (
	PrimaryLanIpPrefix = "192.168.1."

	SecondaryInterfacePrefix = "enx"
	SecondaryLanIpPrefix     = "192.168.0."
	SecondaryLanCidr         = SecondaryLanIpPrefix + "0/24"
)

func EnsureDirectLan(ctx context.Context, peers []string) error {
	ifaces, err := FindSecondaryNetworkInterface(ctx)
	if err != nil {
		return fmt.Errorf("failed to find secondary network interface: %w", err)
	}
	if len(ifaces) == 0 {
		return fmt.Errorf("no interfaces found")
	}

	if err := SetupDirectInterfaces(ctx, ifaces); err != nil {
		return fmt.Errorf("failed to setup direct interfaces: %w", err)
	}
	if len(peers) != 0 {
		fmt.Println("Setting up direct routes for peers:", peers)
		if err := SetDirectRoutes(ctx, ifaces, peers); err != nil {
			return fmt.Errorf("failed to set direct routes: %w", err)
		}
	}
	fmt.Println("Direct LAN setup completed successfully")
	return nil
}

func SetDirectRoutes(ctx context.Context, ifaces []string, peers []string) error {
	iface := ifaces[0]
	existing, err := FindInterfaceRoutes(ctx, iface)
	if err != nil {
		return fmt.Errorf("failed to find existing routes for interface %s: %w", iface, err)
	}
	existing = FilterDirectRoutes(existing)
	existingSet := StringSet(existing)
	toAdd := []string{}
	toDelete := []string{}
	for _, peer := range peers {
		_, has := existingSet[peer]
		delete(existingSet, peer)
		if has {
			fmt.Printf("Route %s already exists for interface %s, skipping\n", peer, iface)
			continue
		}
		fmt.Printf("Route %s does not exist for interface %s, adding\n", peer, iface)
		toAdd = append(toAdd, peer)
	}

	for route := range existingSet {
		fmt.Printf("Route %s exists for interface %s, removing\n", route, iface)
		toDelete = append(toDelete, route)
	}

	for _, route := range toDelete {
		if err := RemoveInterfaceRoute(ctx, iface, route); err != nil {
			return fmt.Errorf("failed to remove route %s for interface %s: %w", route, iface, err)
		}
	}
	for _, route := range toAdd {
		if err := AddInterfaceRoute(ctx, iface, route); err != nil {
			return fmt.Errorf("failed to add route %s for interface %s: %w", route, iface, err)
		}
	}
	fmt.Printf("Successfully updated routes for interface %s: added %d, removed %d\n", iface, len(toAdd), len(toDelete))
	return nil
}

func SetupDirectInterfaces(ctx context.Context, ifaces []string) error {
	iface := ifaces[0]
	fmt.Println("Found secondary network interface:", iface)

	primaryIP, err := FindPrimaryNetworkIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to find primary network IP: %w", err)
	}
	fmt.Println("Found primary network IP:", primaryIP)

	assigned, err := CheckSecondaryLanIp(ctx, iface, primaryIP)
	if err != nil {
		return fmt.Errorf("failed to check secondary LAN IP: %w", err)
	}
	if !assigned {
		if err := SetInterfaceDown(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
		if err := SetInterfaceUp(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface up: %w", err)
		}
		if err := AssignSecondaryLanIp(ctx, iface, primaryIP); err != nil {
			return fmt.Errorf("failed to assign lan ip: %w", err)
		}
	}
	if err := AssignSecondaryLanCidrRoute(ctx, iface); err != nil {
		return fmt.Errorf("failed to assign lan routes: %w", err)
	}
	return nil
}

func FindPrimaryNetworkIP(ctx context.Context) (string, error) {
	fmt.Println("Finding primary network IP")
	return FindInterfaceIP(ctx, PrimaryLanIpPrefix, "")
}

func FindSecondaryNetworkIP(ctx context.Context, iface string) (string, error) {
	fmt.Println("Finding secondary network IP for interface:", iface)
	return FindInterfaceIP(ctx, SecondaryLanIpPrefix, iface)
}

func FindInterfaceIP(ctx context.Context, prefix string, iface string) (string, error) {
	fmt.Println("Finding IP for prefix", prefix, "with interface:", iface)
	args := []string{
		"addr",
		"show",
	}
	if len(iface) > 0 {
		args = append(args, iface)
	}
	output, err := ExecIPCommand(ctx, args...)
	if err != nil {
		return "", err
	}
	str := string(output)
	idx := strings.Index(str, prefix)
	if idx < 0 {
		return "", fmt.Errorf("no network IP found")
	}
	str = str[idx:]
	idx = strings.Index(str, "/")
	if idx < 0 {
		return "", fmt.Errorf("no network IP found")
	}
	str = str[:idx]
	return strings.TrimSpace(str), nil
}

func FindSecondaryNetworkInterface(ctx context.Context) ([]string, error) {
	fmt.Println("Finding secondary network interfaces...")
	output, err := ExecIPCommand(ctx, "link", "list")
	if err != nil {
		return nil, err
	}
	ifaces := []string{}
	idx := -1
	for idx < len(output) {
		idx = strings.Index(string(output), SecondaryInterfacePrefix)
		if idx < 0 {
			return nil, fmt.Errorf("no secondary interface found")
		}
		cut := string(output)[idx:]
		idx = strings.Index(cut, ":")
		if idx < 0 {
			return nil, fmt.Errorf("no secondary interface found")
		}
		iface := strings.TrimSpace(cut[:idx])
		output = output[idx+len(iface):]
		ifaces = append(ifaces, strings.TrimSpace(iface))
	}
	fmt.Println("Found secondary network interfaces:", ifaces)
	return ifaces, nil
}

func FilterDirectRoutes(routes []string) []string {
	filtered := []string{}
	for _, route := range routes {
		route = strings.TrimSuffix(route, "/32")
		if strings.Contains(route, "/") {
			continue
		}
		filtered = append(filtered, route)
	}
	return filtered
}

func FindInterfaceRoutes(ctx context.Context, iface string) ([]string, error) {
	fmt.Println("Finding routes for interface:", iface)
	output, err := ExecIPCommand(ctx, "route", "show", "dev", iface)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	routes := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) == 0 {
			continue
		}
		ip := strings.TrimSpace(parts[0])
		routes = append(routes, ip)
	}
	fmt.Println("Found routes for interface", iface, ":", routes)
	return routes, nil
}

func CheckSecondaryLanIp(ctx context.Context, interfaceName, primaryIP string) (bool, error) {
	fmt.Println("Checking if secondary LAN IP is assigned to interface:", interfaceName)
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP)
	existing, err := FindSecondaryNetworkIP(ctx, interfaceName)
	if err != nil {
		return false, err
	}
	fmt.Println("Found existing secondary IP:", existing, "for interface", interfaceName)
	return existing == secondaryIP, nil
}

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string) error {
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP)
	fmt.Println("Assigning secondary LAN IP", secondaryIP, "to interface", interfaceName)
	_, err := ExecIPCommand(ctx, "addr", "show", secondaryIP, "dev", interfaceName)
	return err
}

func CheckSecondaryLanCidrRoute(ctx context.Context, interfaceName string) (bool, error) {
	routes, err := FindInterfaceRoutes(ctx, interfaceName)
	if err != nil {
		return false, fmt.Errorf("failed to find routes for interface %s: %w", interfaceName, err)
	}
	_, exists := StringSet(routes)[SecondaryLanCidr]
	return exists, nil
}

func AssignSecondaryLanCidrRoute(ctx context.Context, interfaceName string) error {
	exists, err := CheckSecondaryLanCidrRoute(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to check secondary LAN CIDR route: %w", err)
	}
	if exists {
		fmt.Println("Secondary LAN CIDR route already exists for interface", interfaceName, ":", SecondaryLanCidr)
		return nil
	}
	fmt.Println("Adding secondary LAN CIDR route", SecondaryLanCidr, "to interface", interfaceName)
	return AddInterfaceRoute(ctx, interfaceName, SecondaryLanCidr)
}

func AddInterfaceRoute(ctx context.Context, iface, cidr string) error {
	fmt.Println("Adding route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "add", cidr, "dev", iface)
	return err
}

func RemoveInterfaceRoute(ctx context.Context, iface, cidr string) error {
	fmt.Println("Removing route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "show", "dev", iface)
	return err
}

func SetInterfaceDown(ctx context.Context, interfaceName string) error {
	fmt.Println("Seetting secondary network interface to down")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "down")
	return err
}

func SetInterfaceUp(ctx context.Context, interfaceName string) error {
	fmt.Println("Seetting secondary network interface to up")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "up")
	return err
}

func ExecIPCommand(ctx context.Context, args ...string) ([]byte, error) {
	// fmt.Println("Executing IP command:", args)
	cmd := exec.CommandContext(ctx,
		"sudo",
		append([]string{"ip"}, args...)...,
	)
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	return cmd.CombinedOutput()
}

func SecondaryIPFromPrimaryIP(primaryIP string) string {
	secondaryIP := fmt.Sprintf("%s%s", SecondaryLanIpPrefix, strings.TrimPrefix(primaryIP, PrimaryLanIpPrefix))
	return secondaryIP
}

func StringSet(s []string) map[string]struct{} {
	set := make(map[string]struct{}, len(s))
	for _, v := range s {
		set[v] = struct{}{}
	}
	return set
}
