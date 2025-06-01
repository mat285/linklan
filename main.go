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
	node := 1 // Example node number, replace with actual logic to determine node
	if err := SetupDirectLan(ctx, node); err != nil {
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

func SetupDirectLan(ctx context.Context, node int) error {
	fmt.Println("Setting up direct LAN link for node", node)
	iface, err := FindSecondaryNetworkInterface(ctx)
	if err != nil {
		return fmt.Errorf("failed to find secondary network interface: %w", err)
	}
	fmt.Println("Found secondary network interface:", iface)
	fmt.Println("Setting up interface to down")
	primaryIP, err := FindPrimaryNetworkIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to find primary network IP: %w", err)
	}
	fmt.Println("Found primary network IP:", primaryIP)
	if err := SetInterfaceDown(ctx, iface); err != nil {
		return fmt.Errorf("failed to set interface down: %w", err)
	}
	if err := SetInterfaceUp(ctx, iface); err != nil {
		return fmt.Errorf("failed to set interface up: %w", err)
	}
	if err := AssignSecondaryLanIp(ctx, iface, primaryIP); err != nil {
		return fmt.Errorf("failed to assign lan ip: %w", err)
	}
	if err := AssignSecondaryLanCidrRoute(ctx, iface); err != nil {
		return fmt.Errorf("failed to assign lan routes: %w", err)
	}
	return nil
}

func FindPrimaryNetworkIP(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx,
		"ip",
		"addr",
		"show",
	).CombinedOutput()
	if err != nil {
		return "", err
	}
	str := string(output)
	idx := strings.Index(str, PrimaryLanIpPrefix)
	if idx < 0 {
		return "", fmt.Errorf("no primary network IP found")
	}
	str = str[idx:]
	idx = strings.Index(str, "/")
	if idx < 0 {
		return "", fmt.Errorf("no primary network IP found")
	}
	str = str[:idx]
	return strings.TrimSpace(str), nil
}

func FindSecondaryNetworkIP(ctx context.Context, iface string) (string, error) {
	fmt.Println("Finding secondary network IP for interface:", iface)
	output, err := exec.CommandContext(ctx,
		"ip",
		"addr",
		"show",
		iface,
	).CombinedOutput()
	if err != nil {
		return "", err
	}
	str := string(output)
	fmt.Println("Output from ip addr show:", str)
	idx := strings.Index(str, SecondaryInterfacePrefix)
	if idx < 0 {
		return "", fmt.Errorf("no secondary network IP found")
	}
	str = str[idx:]
	idx = strings.Index(str, "/")
	if idx < 0 {
		return "", fmt.Errorf("no secondary network IP found")
	}
	str = str[:idx]
	return strings.TrimSpace(str), nil
}

func FindSecondaryNetworkInterface(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx,
		"ip",
		"link",
		"list",
	).CombinedOutput()
	if err != nil {
		return "", err
	}
	idx := strings.Index(string(output), SecondaryInterfacePrefix)
	if idx < 0 {
		return "", fmt.Errorf("no secondary interface found")
	}
	cut := string(output)[idx:]
	idx = strings.Index(cut, ":")
	if idx < 0 {
		return "", fmt.Errorf("no secondary interface found")
	}
	return cut[:idx], nil
}

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string) error {
	secondaryIP := fmt.Sprintf("%s%s", SecondaryLanIpPrefix, strings.TrimPrefix(primaryIP, PrimaryLanIpPrefix))
	existing, err := FindSecondaryNetworkIP(ctx, interfaceName)
	if err == nil && existing == secondaryIP {
		fmt.Println("Secondary LAN IP already assigned:", existing, "to interface", interfaceName)
		return nil
	}
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

func AssignSecondaryLanCidrRoute(ctx context.Context, interfaceName string) error {
	fmt.Println("Adding secondary LAN CIDR route", SecondaryLanCidr, "to interface", interfaceName)
	cmd := exec.CommandContext(ctx,
		"ip",
		"route",
		"add",
		SecondaryLanCidr,
		"dev",
		interfaceName,
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
