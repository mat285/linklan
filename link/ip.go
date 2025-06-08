package link

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/mat285/linklan/log"
)

const (
	PrimaryLanIpPrefix = "192.168.1."

	SecondaryLanIpPrefix = "192.168.0."
	SecondaryLanCidr     = SecondaryLanIpPrefix + "0/24"

	BondInterfaceName = "bond0"
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
		log.Default().Info("Setting up direct routes for peers:", peers)
		if err := SetDirectRoutes(ctx, ifaces, peers); err != nil {
			return fmt.Errorf("failed to set direct routes: %w", err)
		}
	}
	log.Default().Info("Direct LAN setup completed successfully")
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
			log.Default().Infof("Route %s already exists for interface %s, skipping\n", peer, iface)
			continue
		}
		log.Default().Infof("Route %s does not exist for interface %s, adding\n", peer, iface)
		toAdd = append(toAdd, peer)
	}

	for route := range existingSet {
		log.Default().Infof("Route %s exists for interface %s, removing\n", route, iface)
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
	log.Default().Infof("Successfully updated routes for interface %s: added %d, removed %d\n", iface, len(toAdd), len(toDelete))
	return nil
}

func SetupDirectInterfaces(ctx context.Context, ifaces []string) error {
	log.Default().Info("Found secondary network interface:", ifaces)
	primaryIP, err := FindPrimaryNetworkIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to find primary network IP: %w", err)
	}
	log.Default().Info("Found primary network IP:", primaryIP)
	if len(ifaces) > 1 {
		err := HandleBondedInterfaces(ctx, primaryIP, ifaces)
		if err != nil {
			return fmt.Errorf("failed to handle bonded interfaces: %w", err)
		}
		ifaces = append(ifaces, BondInterfaceName)
	}
	for _, iface := range ifaces {
		if err := AssignIPAndCidr(ctx, iface, primaryIP, len(ifaces) == 1 || iface == BondInterfaceName); err != nil {
			return fmt.Errorf("failed to assign IP and CIDR for interface %s: %w", iface, err)
		}
		log.Default().Info("Assigned IP and CIDR for interface:", iface)
	}
	return nil
}

func AssignIPAndCidr(ctx context.Context, iface string, primaryIP string, cidr bool) error {
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
	if cidr {
		if err := AssignSecondaryLanCidrRoute(ctx, iface); err != nil {
			return fmt.Errorf("failed to assign lan routes: %w", err)
		}
	}
	return SetInterfaceUp(ctx, iface)
}

func HandleBondedInterfaces(ctx context.Context, primaryIP string, ifaces []string) error {
	log.Default().Info("Multiple secondary interfaces found, ensuring bond interface is set up")
	if err := EnsureBondInterface(ctx); err != nil {
		return fmt.Errorf("failed to ensure bond interface: %w", err)
	}
	unboundIfaces, err := UnbondedInterfaces(ctx, ifaces)
	if err != nil {
		return fmt.Errorf("failed to find unbonded interfaces: %w", err)
	}
	if len(unboundIfaces) > 0 {
		if err := BondInterfaces(ctx, unboundIfaces); err != nil {
			return fmt.Errorf("failed to bond interfaces: %w", err)
		}
	}
	log.Default().Info("All interfaces are bonded to", BondInterfaceName)
	return nil
}

func EnsureBondInterface(ctx context.Context) error {
	log.Default().Info("Ensuring bond interface is set up")
	if err := exec.CommandContext(ctx, "modprobe", "bonding").Run(); err != nil {
		return fmt.Errorf("failed to load bonding module: %w", err)
	}
	output, err := ExecIPCommand(ctx, "link", "show") // Clean up any existing bond
	if err != nil {
		return fmt.Errorf("failed to check existing bond interface: %w", err)
	}
	if strings.Contains(string(output), BondInterfaceName) {
		log.Default().Info("Bond interface bond0 already exists")
		return nil // Bond interface already exists, no need to create it
	}

	log.Default().Info("Creating new bond interface bond0 with mode 802.3ad")
	args := []string{"link", "add", BondInterfaceName, "type", "bond", "mode", "802.3ad"}
	if _, err := ExecIPCommand(ctx, args...); err != nil {
		return fmt.Errorf("failed to create bond interface: %w", err)
	} // Create new bond interface
	log.Default().Info("Successfully ensured bond interface is set up")
	return nil
}

func UnbondedInterfaces(ctx context.Context, ifaces []string) ([]string, error) {
	unbound := []string{}
	for _, iface := range ifaces {
		log.Default().Info("Checking if interface", iface, "is unbonded")
		output, err := ExecIPCommand(ctx, "link", "show", iface)
		if err != nil {
			return nil, fmt.Errorf("failed to check interface %s: %w", iface, err)
		}
		if strings.Contains(string(output), "master "+BondInterfaceName) {
			log.Default().Info("Interface", iface, "is bonded ", BondInterfaceName)
			continue
		}
		log.Default().Info("Interface", iface, "is unbonded")
		unbound = append(unbound, iface)
	}
	return unbound, nil
}

func RemoveBondInterfaces(ctx context.Context, ifaces []string) error {
	log.Default().Info("Removing bond from secondary interfaces:", ifaces)
	if len(ifaces) == 0 {
		return fmt.Errorf("no interfaces to unbond")
	}
	for _, iface := range ifaces {
		log.Default().Info("Removing interface", iface, "from bond0")
		if _, err := ExecIPCommand(ctx, "link", "set", iface, "nomaster"); err != nil {
			return fmt.Errorf("failed to remove interface %s from bond: %w", iface, err)
		}
		if err := SetInterfaceDown(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
	}
	log.Default().Info("Successfully removed bond from interfaces:", ifaces)
	return nil
}

func BondInterfaces(ctx context.Context, ifaces []string) error {
	log.Default().Info("Bonding secondary interfaces:", ifaces)
	if len(ifaces) == 0 {
		return fmt.Errorf("no interfaces to bond")
	}
	for _, iface := range ifaces {
		if err := SetInterfaceDown(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
		log.Default().Info("Adding interface", iface, "to bond0")
		if _, err := ExecIPCommand(ctx, "link", "set", iface, "master", BondInterfaceName); err != nil {
			return fmt.Errorf("failed to add interface %s to bond: %w", iface, err)
		}
	}
	log.Default().Info("Successfully bonded interfaces:", ifaces)
	return nil
}

func FindPrimaryNetworkIP(ctx context.Context) (string, error) {
	log.Default().Info("Finding primary network IP")
	return FindInterfaceIP(ctx, PrimaryLanIpPrefix, "")
}

func FindSecondaryNetworkIP(ctx context.Context, iface string) (string, error) {
	log.Default().Info("Finding secondary network IP for interface:", iface)
	return FindInterfaceIP(ctx, SecondaryLanIpPrefix, iface)
}

func FindInterfaceIP(ctx context.Context, prefix string, iface string) (string, error) {
	log.Default().Info("Finding IP for prefix", prefix, "with interface:", iface)
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
	log.Default().Info("Finding secondary network interfaces...")
	_, ifaces, err := FindPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no secondary network interfaces found")
	}
	strs := make([]string, len(ifaces))
	for i, iface := range ifaces {
		strs[i] = iface.Name
	}
	log.Default().Info("Found secondary network interfaces:", strs)
	return strs, nil
}

func FindPhysicalInterfaces() (primary *net.Interface, filtered []net.Interface, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}
	log.Default().Info("Found network interfaces:", len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			log.Default().Info("Skipping loopback interface:", iface.Name)
			continue
		}
		if IsFilteredInterface(iface) {
			log.Default().Info("Skipping known virtual interface:", iface.Name)
			continue
		}
		isHardware, err := IsHardwareInterface(iface)
		if err != nil {
			log.Default().Info("Error checking if interface is hardware:", iface.Name, err)
			continue
		}
		if !isHardware {
			log.Default().Info("Skipping non-hardware interface:", iface.Name)
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.Default().Info("Error getting addresses for interface:", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), PrimaryLanIpPrefix) {
				primary = &iface
				log.Default().Info("Found primary network interface:", iface.Name)
				break
			}
		}
		if primary != nil && primary == &iface {
			log.Default().Info("Primary network interface already found, skipping further checks for:", iface.Name)
			continue
		}
		log.Default().Info("Including hardware interface:", iface.Name)
		filtered = append(filtered, iface)
	}
	if primary == nil {
		return nil, filtered, fmt.Errorf("no primary network interface found")
	}
	return primary, filtered, nil
}

func IsHardwareInterface(iface net.Interface) (bool, error) {
	dir := "/sys/class/net/" + iface.Name
	info, err := os.Lstat(dir)
	if err != nil {
		return false, fmt.Errorf("failed to get interface info for %s: %w", iface.Name, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("interface %s is not a symlink", iface.Name)
	}
	rl, err := os.Readlink(dir)
	if err != nil {
		return false, fmt.Errorf("failed to read symlink for interface %s: %w", iface.Name, err)
	}
	return !strings.Contains(rl, "devices/virtual/"), nil
}

func IsFilteredInterface(iface net.Interface) bool {
	virtualIfacePrefixes := []string{
		"lo",
		"tun",
		"veth",
		"vxlan",
		"docker",
		"br-",
		"tailscale0",
		"cali", // calico
	}
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			log.Default().Info("Skipping known virtual interface:", iface.Name)
			return true
		}
	}
	return false
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
	log.Default().Info("Finding routes for interface:", iface)
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
	log.Default().Info("Found routes for interface", iface, ":", routes)
	return routes, nil
}

func CheckSecondaryLanIp(ctx context.Context, interfaceName, primaryIP string) (bool, error) {
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP)
	parsedSecondaryIP := net.ParseIP(secondaryIP)
	if parsedSecondaryIP == nil {
		return false, fmt.Errorf("invalid secondary IP format: %s", secondaryIP)
	}
	if parsedSecondaryIP.To4() == nil {
		return false, fmt.Errorf("secondary IP is not an IPv4 address: %s", secondaryIP)
	}
	log.Default().Info("Checking if secondary LAN IP is assigned to interface:", interfaceName, "secondary IP:", secondaryIP)
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return false, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}
	if iface == nil {
		return false, fmt.Errorf("interface %s not found", interfaceName)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}
	for _, addr := range addrs {
		log.Default().Info("Checking address for interface", interfaceName, ":", addr.String())
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			log.Default().Info("Skipping non-IP address for interface", interfaceName, ":", addr)
			continue
		}
		if ipNet.IP.To4() == nil {
			log.Default().Info("Skipping non-IPv4 address for interface", interfaceName, ":", ipNet.IP)
			continue
		}
		if ipNet.Contains(parsedSecondaryIP) {
			log.Default().Info("Found secondary IP", secondaryIP, "assigned to interface", interfaceName)
			return true, nil
		}
	}
	log.Default().Info("No addresses found for interface", interfaceName, "assuming it is not assigned")
	return false, nil
}

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string) error {
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP)
	log.Default().Info("Assigning secondary LAN IP", secondaryIP, "to interface", interfaceName)
	_, err := ExecIPCommand(ctx, "addr", "add", secondaryIP, "dev", interfaceName)
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
		log.Default().Info("Secondary LAN CIDR route already exists for interface", interfaceName, ":", SecondaryLanCidr)
		return nil
	}
	log.Default().Info("Adding secondary LAN CIDR route", SecondaryLanCidr, "to interface", interfaceName)
	return AddInterfaceRoute(ctx, interfaceName, SecondaryLanCidr)
}

func AddInterfaceRoute(ctx context.Context, iface, cidr string) error {
	log.Default().Info("Adding route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "add", cidr, "dev", iface)
	return err
}

func RemoveInterfaceRoute(ctx context.Context, iface, cidr string) error {
	log.Default().Info("Removing route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "del", cidr, "dev", iface)
	return err
}

func SetInterfaceDown(ctx context.Context, interfaceName string) error {
	log.Default().Info("Seetting secondary network interface to down")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "down")
	return err
}

func SetInterfaceUp(ctx context.Context, interfaceName string) error {
	log.Default().Info("Seetting secondary network interface to up")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "up")
	return err
}

func ExecIPCommand(ctx context.Context, args ...string) ([]byte, error) {
	log.Default().Info("Executing IP command: ip", args)
	cmd := exec.CommandContext(ctx,
		"ip",
		args...,
	)
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
