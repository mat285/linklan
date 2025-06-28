package link

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/mat285/linklan/config"
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
	if len(ifaces) == 0 {
		return fmt.Errorf("no secondary network interfaces found")
	}
	log.Default().Info("Found secondary network interface:", ifaces)
	primaryIP, err := FindPrimaryNetworkIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to find primary network IP: %w", err)
	}
	log.Default().Info("Found primary network IP:", primaryIP)
	sort.Strings(ifaces)
	iface := ifaces[0]
	if err := AssignIPAndCidr(ctx, iface, primaryIP, 0, len(ifaces) == 1 || iface == BondInterfaceName); err != nil {
		return fmt.Errorf("failed to assign IP and CIDR for interface %s: %w", iface, err)
	}
	log.Default().Info("Assigned IP and CIDR for interface:", iface)
	return nil
}

func AssignIPAndCidr(ctx context.Context, iface string, primaryIP string, index int, cidr bool) error {
	assigned, err := CheckSecondaryLanIp(ctx, iface, primaryIP, index)
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
		if err := AssignSecondaryLanIp(ctx, iface, primaryIP, index); err != nil {
			return fmt.Errorf("failed to assign lan ip: %w", err)
		}
	}
	if cidr {
		if err := AssignSecondaryLanCidrRoute(ctx, iface, index); err != nil {
			return fmt.Errorf("failed to assign lan routes: %w", err)
		}
	}
	return SetInterfaceUp(ctx, iface)
}

func FindPrimaryNetworkIP(ctx context.Context) (string, error) {
	log.Default().Info("Finding primary network IP")
	prefix := PrimaryLanIpPrefix
	cfg := config.GetConfig(ctx)
	if cfg != nil && cfg.Lan.CIDR != "" {
		log.Default().Info("Using configured primary network CIDR:", cfg.Lan.CIDR)
		var err error
		prefix, err = CIDRToPrefix(cfg.Lan.CIDR)
		if err != nil {
			return "", fmt.Errorf("failed to convert CIDR to prefix: %w", err)
		}
	}
	return FindInterfaceIP(ctx, prefix, "")
}

func FindSecondaryNetworkIP(ctx context.Context, iface string, index int) (string, error) {
	log.Default().Info("Finding secondary network IP for interface:", iface)
	prefix := SecondaryLanIpPrefix
	cfg := config.GetConfig(ctx)
	if cfg != nil && len(cfg.Lan.CIDR) > 0 {
		if index < 0 {
			for i, ifce := range cfg.Interfaces {
				if ifce.MatchesName(iface) {
					index = i
					break
				}
			}
		}
		if index < 0 {
			return "", fmt.Errorf("index %d out of bounds for secondary CIDRs", index)
		}
		cidr, err := CIDRForIndex(cfg.Lan.CIDR, index)
		if err != nil {
			return "", fmt.Errorf("failed to get CIDR for index %d: %w", index, err)
		}
		log.Default().Info("Using configured secondary network CIDR:", cidr)
		prefix, err = CIDRToPrefix(cidr)
		if err != nil {
			return "", fmt.Errorf("failed to convert CIDR to prefix: %w", err)
		}
	}
	return FindInterfaceIP(ctx, prefix, iface)
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
		valid, prime, err := IsSecondaryNetworkInterface(iface)
		if err != nil {
			log.Default().Info("Error checking interface:", iface.Name, err)
			continue
		}
		if prime != nil {
			if primary != nil {
				log.Default().Info("Multiple primary interfaces found, skipping:", iface.Name)
				continue // Skip if we already found a primary
			}
			primary = prime
		}
		if !valid {
			log.Default().Debugf("Skipping interface:", iface.Name)
			continue
		}
		filtered = append(filtered, iface)
	}
	if primary == nil {
		return nil, filtered, fmt.Errorf("no primary network interface found")
	}
	return primary, filtered, nil
}

func IsSecondaryNetworkInterface(iface net.Interface) (bool, *net.Interface, error) {
	if iface.Flags&net.FlagLoopback != 0 {
		log.Default().Debugf("Skipping loopback interface:", iface.Name)
		return false, nil, nil
	}
	if IsFilteredInterface(iface) {
		log.Default().Debugf("Skipping known virtual interface:", iface.Name)
		return false, nil, nil
	}
	isHardware, err := IsHardwareInterface(iface)
	if err != nil {
		log.Default().Info("Error checking if interface is hardware:", iface.Name, err)
		return false, nil, err
	}
	if !isHardware {
		log.Default().Debugf("Skipping non-hardware interface:", iface.Name)
		return false, nil, nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		log.Default().Info("Error getting addresses for interface:", iface.Name, err)
		return false, nil, err
	}
	for _, addr := range addrs {
		if strings.HasPrefix(addr.String(), PrimaryLanIpPrefix) {
			log.Default().Info("Found primary network interface:", iface.Name)
			return false, &iface, nil // This is the primary interface
		}
	}
	log.Default().Info("Including hardware interface:", iface.Name)
	return true, nil, nil // This is a secondary interface
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
		"w",    // wifi
	}
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			log.Default().Debugf("Skipping known virtual interface:", iface.Name)
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

func CheckSecondaryLanIp(ctx context.Context, interfaceName, primaryIP string, index int) (bool, error) {
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP, index)
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
			log.Default().Debugf("Skipping non-IP address for interface", interfaceName, ":", addr)
			continue
		}
		if ipNet.IP.To4() == nil {
			log.Default().Debugf("Skipping non-IPv4 address for interface", interfaceName, ":", ipNet.IP)
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

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string, index int) error {
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP, index)
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

func AssignSecondaryLanCidrRoute(ctx context.Context, interfaceName string, index int) error {
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

func SecondaryIPFromPrimaryIP(primaryIP string, index int) string {
	ip, _ := CIDRForIndex(primaryIP, index)
	return ip
	// secondaryIP := fmt.Sprintf("%s%s", , strings.TrimPrefix(primaryIP, PrimaryLanIpPrefix))
	// return secondaryIP
}

func StringSet(s []string) map[string]struct{} {
	set := make(map[string]struct{}, len(s))
	for _, v := range s {
		set[v] = struct{}{}
	}
	return set
}

func CIDRToPrefix(cidr string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR format: %w", err)
	}
	bits, _ := ipNet.Mask.Size()
	switch bits {
	case 8, 16, 24:
		take := (bits / 8)
		ret := ip.String()
		count := 0
		i := 0
		for count < take {
			if ret[i] == '.' {
				count++
			}
			i++
		}
		return ret[:i], nil
	default:
		return "", fmt.Errorf("unsupported CIDR size: %d bits", bits)
	}
}

func CIDRSize(cidr string) (int, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return -1, fmt.Errorf("invalid CIDR format: %w", err)
	}
	bits, _ := ipNet.Mask.Size()
	return bits, nil
}

func PartialIPString(ip string, size int) (string, error) {
	if size == 0 {
		return "", nil
	}
	if size < 1 || size > 4 {
		return "", fmt.Errorf("size must be between 1 and 4")
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP format: %s", ip)
	}
	return strings.Join(parts[:size], "."), nil
}

func CIDRLastSpecified(cidr string) (int, error) {
	size, err := CIDRSize(cidr)
	if err != nil {
		return -1, fmt.Errorf("failed to get CIDR size: %w", err)
	}
	parts := strings.Split(cidr, ".")
	if len(parts) != 4 {
		return -1, fmt.Errorf("invalid CIDR format: %s", cidr)
	}
	idx := size/8 - 1
	return strconv.Atoi(parts[idx])
}

func CIDRForIndex(primary string, idx int) (string, error) {
	size, err := CIDRSize(primary)
	if err != nil {
		return "", fmt.Errorf("failed to get CIDR size: %w", err)
	}
	count := size/8 - 1
	primaryIP, err := PartialIPString(primary, count)
	if err != nil {
		return "", fmt.Errorf("failed to get partial primary IP string: %w", err)
	}
	lastPrimary, err := CIDRLastSpecified(primary)
	if err != nil {
		return "", fmt.Errorf("failed to get last specified CIDR: %w", err)
	}
	fmt.Println("Last primary:", lastPrimary, "Index:", idx, "Size:", size, "Count:", count)
	if size == 8 {
		idx++
	}
	if idx >= lastPrimary {
		idx = lastPrimary + idx
	}
	if len(primaryIP) > 0 {
		primaryIP += "."
	}
	cidr := fmt.Sprintf("%s%d", primaryIP, idx)
	count++
	for count < 4 {
		cidr += ".0"
		count++
	}
	cidr += fmt.Sprintf("/%d", size)
	return cidr, nil
}
