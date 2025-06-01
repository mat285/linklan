package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	ctx := context.Background()
	if err := EnsureDirectLan(ctx, []string{"192.168.1.207"}); err != nil {
		fmt.Fprintln(os.Stderr, "Error setting up direct LAN:", err)
		os.Exit(1)
	}
	fmt.Println("Direct LAN setup completed successfully")
	os.Exit(0)
}

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
	if err := SetDirectRoutes(ctx, ifaces, peers); err != nil {
		return fmt.Errorf("failed to set direct routes: %w", err)
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
	toAdd := []string{}
	toDelete := []string{}
	for _, peer := range peers {
		_, has := existing[peer]
		delete(existing, peer)
		if has {
			fmt.Printf("Route %s already exists for interface %s, skipping\n", peer, iface)
			continue
		}
		fmt.Printf("Route %s does not exist for interface %s, adding\n", peer, iface)
		toAdd = append(toAdd, peer)
	}

	for route := range existing {
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
		"addr", "show",
	}
	if len(iface) > 0 {
		args = append(args, iface)
	}
	output, err := exec.CommandContext(ctx,
		"ip",
		args...,
	).CombinedOutput()
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
	output, err := exec.CommandContext(ctx,
		"ip",
		"link",
		"list",
	).CombinedOutput()
	if err != nil {
		return nil, err
	}
	idx := strings.Index(string(output), SecondaryInterfacePrefix)
	if idx < 0 {
		return nil, fmt.Errorf("no secondary interface found")
	}
	cut := string(output)[idx:]
	idx = strings.Index(cut, ":")
	if idx < 0 {
		return nil, fmt.Errorf("no secondary interface found")
	}
	ifaces := []string{cut[:idx]}
	fmt.Println("Found secondary network interfaces:", ifaces)
	return ifaces, nil
}

func FilterDirectRoutes(routes map[string]struct{}) map[string]struct{} {
	filtered := map[string]struct{}{}
	for route := range routes {
		route = strings.TrimSuffix(route, "/32")
		if strings.Contains(route, "/") {
			continue
		}
		filtered[route] = struct{}{}
	}
	return filtered
}

func FindInterfaceRoutes(ctx context.Context, iface string) (map[string]struct{}, error) {
	fmt.Println("Finding single routes for interface:", iface)
	output, err := exec.CommandContext(ctx,
		"ip",
		"route",
		"show",
		"dev",
		iface,
	).CombinedOutput()
	if err != nil {
		return nil, err
	}
	fmt.Println(string(output))
	lines := strings.Split(string(output), "\n")
	routes := map[string]struct{}{}
	for _, line := range lines {
		fmt.Println("route entry", line)
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(line, iface) {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) == 0 {
			continue
		}
		ip := strings.TrimSpace(parts[0])
		routes[ip] = struct{}{}
	}
	fmt.Println("Found routes for interface", iface, ":", routes)
	return routes, nil
}

func CheckSecondaryLanIp(ctx context.Context, interfaceName, primaryIP string) (bool, error) {
	fmt.Println("Checking if secondary LAN IP is assigned to interface:", interfaceName)
	secondaryIP := fmt.Sprintf("%s%s", SecondaryLanIpPrefix, strings.TrimPrefix(PrimaryLanIpPrefix, PrimaryLanIpPrefix))
	existing, err := FindSecondaryNetworkIP(ctx, interfaceName)
	if err != nil {
		return false, err
	}
	fmt.Println("Found existing secondary IP:", existing, "for interface", interfaceName)
	return existing == secondaryIP, nil
}

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string) error {
	secondaryIP := fmt.Sprintf("%s%s", SecondaryLanIpPrefix, strings.TrimPrefix(primaryIP, PrimaryLanIpPrefix))
	fmt.Println("Assigning secondary LAN IP", secondaryIP, "to interface", interfaceName)
	cmd := exec.CommandContext(ctx,
		"ip",
		"addr",
		"add",
		secondaryIP,
		"dev",
		interfaceName,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func CheckSecondaryLanCidrRoute(ctx context.Context, interfaceName string) (bool, error) {
	routes, err := FindInterfaceRoutes(ctx, interfaceName)
	if err != nil {
		return false, fmt.Errorf("failed to find routes for interface %s: %w", interfaceName, err)
	}
	_, exists := routes[SecondaryLanCidr]
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
	cmd := exec.CommandContext(ctx,
		"ip",
		"route",
		"add",
		cidr,
		"dev",
		iface,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RemoveInterfaceRoute(ctx context.Context, iface, cidr string) error {
	fmt.Println("Removing route", cidr, "to interface", iface)
	cmd := exec.CommandContext(ctx,
		"ip",
		"route",
		"delete",
		cidr,
		"dev",
		iface,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func SetInterfaceDown(ctx context.Context, interfaceName string) error {
	fmt.Println("Seetting secondary network interface to down")
	cmd := exec.CommandContext(ctx,
		"ip",
		"link",
		"set",
		interfaceName,
		"down",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func SetInterfaceUp(ctx context.Context, interfaceName string) error {
	fmt.Println("Seetting secondary network interface to up")
	cmd := exec.CommandContext(ctx,
		"ip",
		"link",
		"set",
		interfaceName,
		"up",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
