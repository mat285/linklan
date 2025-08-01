package link

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
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
		log.GetLogger(ctx).Info("Setting up direct routes for peers:", peers)
		if err := SetDirectRoutes(ctx, ifaces, peers); err != nil {
			return fmt.Errorf("failed to set direct routes: %w", err)
		}
	}
	log.GetLogger(ctx).Info("Direct LAN setup completed successfully")
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
			log.GetLogger(ctx).Infof("Route %s already exists for interface %s, skipping\n", peer, iface)
			continue
		}
		log.GetLogger(ctx).Infof("Route %s does not exist for interface %s, adding\n", peer, iface)
		toAdd = append(toAdd, peer)
	}

	for route := range existingSet {
		log.GetLogger(ctx).Infof("Route %s exists for interface %s, removing\n", route, iface)
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
	log.GetLogger(ctx).Infof("Successfully updated routes for interface %s: added %d, removed %d\n", iface, len(toAdd), len(toDelete))
	return nil
}

func SetupDirectInterfaces(ctx context.Context, ifaces []string) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("no secondary network interfaces found")
	}
	log.GetLogger(ctx).Info("Found secondary network interface:", ifaces)
	primaryIP, _, err := FindPrimaryNetworkIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to find primary network IP: %w", err)
	}
	log.GetLogger(ctx).Info("Found primary network IP:", primaryIP)
	cfg := config.GetConfig(ctx)
	cfg.SortInterfaces(ifaces)
	for i, iface := range ifaces {
		log.GetLogger(ctx).Infof("Setting up interface %s with index %d", iface, i)
		if err := AssignIPAndCidr(ctx, iface, primaryIP, byte(i), true); err != nil {
			return fmt.Errorf("failed to assign IP and CIDR for interface %s: %w", iface, err)
		}
		log.GetLogger(ctx).Info("Assigned IP and CIDR for interface:", iface)
	}
	return nil
}

func AssignIPAndCidr(ctx context.Context, iface string, primaryIP string, index byte, cidr bool) error {
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

func FindPrimaryNetworkIP(ctx context.Context) (string, *net.Interface, error) {
	log.GetLogger(ctx).Info("Finding primary network IP")
	prefix := PrimaryLanIpPrefix
	cfg := config.GetConfig(ctx)
	if cfg != nil && cfg.Lan.CIDR != "" {
		log.GetLogger(ctx).Info("Using configured primary network CIDR:", cfg.Lan.CIDR)
		var err error
		prefix, err = CIDRToPrefix(cfg.Lan.CIDR)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert CIDR to prefix: %w", err)
		}
	}
	return FindInterfaceIP(ctx, prefix, "")
}

func FindSecondaryNetworkIP(ctx context.Context, iface string, index int) (string, error) {
	log.GetLogger(ctx).Info("Finding secondary network IP for interface:", iface)
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
		cidr, err := CIDRForIndex(cfg.Lan.CIDR, byte(index))
		if err != nil {
			return "", fmt.Errorf("failed to get CIDR for index %d: %w", index, err)
		}
		log.GetLogger(ctx).Info("Using configured secondary network CIDR:", cidr)
		prefix, err = CIDRToPrefix(cidr)
		if err != nil {
			return "", fmt.Errorf("failed to convert CIDR to prefix: %w", err)
		}
	}
	ipstr, _, err := FindInterfaceIP(ctx, prefix, iface)
	return ipstr, err
}

func FindInterfaceIP(ctx context.Context, prefix string, inter string) (string, *net.Interface, error) {
	log.GetLogger(ctx).Info("Finding IP for prefix", prefix, "with interface:", inter)
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return "", nil, fmt.Errorf("no network interfaces found")
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.GetLogger(ctx).Info("Error getting addresses for interface:", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				log.GetLogger(ctx).Debugf("Skipping non-IP address for interface %s: %v", iface.Name, addr)
				continue
			}
			if ipNet.IP.To4() == nil {
				log.GetLogger(ctx).Debugf("Skipping non-IPv4 address for interface %s: %v", iface.Name, ipNet.IP)
				continue
			}
			if strings.HasPrefix(ipNet.IP.String(), prefix) {
				if inter == "" || iface.Name == inter {
					log.GetLogger(ctx).Info("Found matching IP for prefix", prefix, "on interface", iface.Name, ":", ipNet.IP.String())
					return ipNet.IP.String(), &iface, nil
				}
				log.GetLogger(ctx).Info("Found matching IP for prefix", prefix, "on interface", iface.Name, ":", ipNet.IP.String())
			}
		}
	}
	log.GetLogger(ctx).Info("No matching IP found for prefix", prefix, "on interface", inter)
	return "", nil, fmt.Errorf("no matching IP found for prefix %s on interface %s", prefix, inter)
	// args := []string{
	// 	"addr",
	// 	"show",
	// }
	// if len(iface) > 0 {
	// 	args = append(args, iface)
	// }
	// output, err := ExecIPCommand(ctx, args...)
	// if err != nil {
	// 	return "", err
	// }
	// str := string(output)
	// idx := strings.Index(str, prefix)
	// if idx < 0 {
	// 	return "", fmt.Errorf("no network IP found")
	// }
	// str = str[idx:]
	// idx = strings.Index(str, "/")
	// if idx < 0 {
	// 	return "", fmt.Errorf("no network IP found")
	// }
	// str = str[:idx]
	// return strings.TrimSpace(str), nil
}

func FindSecondaryNetworkInterface(ctx context.Context) ([]string, error) {
	log.GetLogger(ctx).Info("Finding secondary network interfaces...")
	_, ifaces, err := FindPhysicalInterfaces(ctx)
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
	log.GetLogger(ctx).Info("Found secondary network interfaces:", strs)
	return strs, nil
}

func FindPhysicalInterfaces(ctx context.Context) (primary *net.Interface, filtered []net.Interface, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}
	log.GetLogger(ctx).Info("Found network interfaces:", len(ifaces))
	for _, iface := range ifaces {
		valid, prime, err := IsSecondaryNetworkInterface(ctx, iface)
		if err != nil {
			log.GetLogger(ctx).Info("Error checking interface:", iface.Name, err)
			continue
		}
		if prime != nil {
			if primary != nil {
				log.GetLogger(ctx).Info("Multiple primary interfaces found, skipping:", iface.Name)
				continue // Skip if we already found a primary
			}
			primary = prime
		}
		if !valid {
			log.GetLogger(ctx).Debugf("Skipping interface: %s", iface.Name)
			continue
		}
		filtered = append(filtered, iface)
	}
	if primary == nil {
		_, priface, err := FindPrimaryNetworkIP(ctx)
		if err != nil {
			return nil, filtered, fmt.Errorf("failed to find primary network IP: %w", err)
		}
		if priface == nil {
			return nil, filtered, fmt.Errorf("no primary network interface found")
		}
		primary = priface
		log.GetLogger(ctx).Info("Using primary network interface:", primary.Name)
	}
	return primary, filtered, nil
}

func IsSecondaryNetworkInterface(ctx context.Context, iface net.Interface) (bool, *net.Interface, error) {
	prefix := PrimaryLanIpPrefix
	cfg := config.GetConfig(ctx)
	if cfg != nil && cfg.Lan.CIDR != "" {
		log.GetLogger(ctx).Info("Using configured primary network CIDR:", cfg.Lan.CIDR)
		var err error
		prefix, err = CIDRToPrefix(cfg.Lan.CIDR)
		if err != nil {
			return false, nil, fmt.Errorf("failed to convert CIDR to prefix: %w", err)
		}
	}

	if iface.Flags&net.FlagLoopback != 0 {
		log.GetLogger(ctx).Debug("Skipping loopback interface:", iface.Name)
		return false, nil, nil
	}
	if IsFilteredInterface(iface) {
		log.GetLogger(ctx).Debug("Skipping known virtual interface:", iface.Name)
		return false, nil, nil
	}

	if IsBridgeInterface(ctx, iface) {
		return true, nil, nil
	}
	isHardware, err := IsHardwareInterface(iface)
	if err != nil {
		log.GetLogger(ctx).Info("Error checking if interface is hardware:", iface.Name, err)
		return false, nil, err
	}
	if !isHardware {
		log.GetLogger(ctx).Debug("Skipping non-hardware interface:", iface.Name)
		return false, nil, nil
	}
	for _, ifc := range config.GetConfig(ctx).Interfaces {
		log.GetLogger(ctx).Debugf("Checking interface %s against config interface %v", iface.Name, ifc)
		if ifc.MatchesName(iface.Name) && ifc.Disabled {
			log.GetLogger(ctx).Info("Skipping disabled interface:", iface.Name)
			return false, nil, nil
		}
	}
	addrs, err := iface.Addrs()
	if err != nil {
		log.GetLogger(ctx).Info("Error getting addresses for interface:", iface.Name, err)
		return false, nil, err
	}
	for _, addr := range addrs {
		addrIPNet, ok := addr.(*net.IPNet)
		if !ok {
			log.GetLogger(ctx).Debugf("Skipping non-IP address for interface %s: %v", iface.Name, addr)
			continue
		}
		if addrIPNet.IP.To4() == nil {
			log.GetLogger(ctx).Debugf("Skipping non-IPv4 address for interface %s: %v", iface.Name, addrIPNet.IP)
			continue
		}
		if strings.HasPrefix(addrIPNet.IP.String(), prefix) {
			log.GetLogger(ctx).Info("Found primary network interface:", iface.Name)
			return false, &iface, nil // This is the primary interface
		}
	}
	log.GetLogger(ctx).Info("Including hardware interface:", iface.Name)
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

func IsBridgeInterface(ctx context.Context, iface net.Interface) bool {
	output, err := ExecIPCommand(context.Background(), "link", "show", iface.Name, "type", "bridge")
	if err != nil {
		log.GetLogger(ctx).Debugf("Error checking if interface %s is a bridge: %v", iface.Name, err)
		return false
	}
	return strings.Contains(string(output), iface.Name)
}

func IsFilteredInterface(iface net.Interface) bool {
	virtualIfacePrefixes := []string{
		"lo",
		"tun",
		"veth",
		"vxlan",
		"docker",
		"tailscale0",
		"cali", // calico
		"w",    // wifi
	}
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			// log.GetLogger(ctx).Debugf("Skipping known virtual interface:", iface.Name)
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
	log.GetLogger(ctx).Info("Finding routes for interface:", iface)
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
	log.GetLogger(ctx).Info("Found routes for interface", iface, ":", routes)
	return routes, nil
}

func CheckSecondaryLanIp(ctx context.Context, interfaceName, primaryIP string, index byte) (bool, error) {
	secondaryIP, err := SecondaryIPFromPrimaryIP(ctx, primaryIP, index)
	if err != nil {
		return false, fmt.Errorf("failed to get secondary IP from primary IP: %w", err)
	}
	parsedSecondaryIP := net.ParseIP(secondaryIP)
	if parsedSecondaryIP == nil {
		return false, fmt.Errorf("invalid secondary IP format: %q", secondaryIP)
	}
	if parsedSecondaryIP.To4() == nil {
		return false, fmt.Errorf("secondary IP is not an IPv4 address: %s", secondaryIP)
	}
	log.GetLogger(ctx).Info("Checking if secondary LAN IP is assigned to interface:", interfaceName, "secondary IP:", secondaryIP)
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
		log.GetLogger(ctx).Info("Checking address for interface", interfaceName, ":", addr.String())
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			log.GetLogger(ctx).Debugf("Skipping non-IP address for interface", interfaceName, ":", addr)
			continue
		}
		if ipNet.IP.To4() == nil {
			log.GetLogger(ctx).Debugf("Skipping non-IPv4 address for interface", interfaceName, ":", ipNet.IP)
			continue
		}
		if ipNet.Contains(parsedSecondaryIP) {
			log.GetLogger(ctx).Info("Found secondary IP", secondaryIP, "assigned to interface", interfaceName)
			return true, nil
		}
	}
	log.GetLogger(ctx).Info("No addresses found for interface", interfaceName, "assuming it is not assigned")
	return false, nil
}

func AssignSecondaryLanIp(ctx context.Context, interfaceName string, primaryIP string, index byte) error {
	secondaryIP, err := SecondaryIPFromPrimaryIP(ctx, primaryIP, index)
	if err != nil {
		return fmt.Errorf("failed to get secondary IP from primary IP: %w", err)
	}
	log.GetLogger(ctx).Info("Assigning secondary LAN IP", secondaryIP, "to interface", interfaceName)
	_, err = ExecIPCommand(ctx, "addr", "add", secondaryIP, "dev", interfaceName)
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

func AssignSecondaryLanCidrRoute(ctx context.Context, interfaceName string, index byte) error {
	exists, err := CheckSecondaryLanCidrRoute(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to check secondary LAN CIDR route: %w", err)
	}
	if exists {
		log.GetLogger(ctx).Info("Secondary LAN CIDR route already exists for interface", interfaceName, ":", SecondaryLanCidr)
		return nil
	}
	log.GetLogger(ctx).Info("Adding secondary LAN CIDR route", SecondaryLanCidr, "to interface", interfaceName)
	return AddInterfaceRoute(ctx, interfaceName, SecondaryLanCidr)
}

func AddInterfaceRoute(ctx context.Context, iface, cidr string) error {
	log.GetLogger(ctx).Info("Adding route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "add", cidr, "dev", iface)
	return err
}

func RemoveInterfaceRoute(ctx context.Context, iface, cidr string) error {
	log.GetLogger(ctx).Info("Removing route", cidr, "to interface", iface)
	_, err := ExecIPCommand(ctx, "route", "del", cidr, "dev", iface)
	return err
}

func SetInterfaceDown(ctx context.Context, interfaceName string) error {
	log.GetLogger(ctx).Info("Seetting secondary network interface to down")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "down")
	return err
}

func SetInterfaceUp(ctx context.Context, interfaceName string) error {
	log.GetLogger(ctx).Info("Seetting secondary network interface to up")
	_, err := ExecIPCommand(ctx, "link", "set", interfaceName, "up")
	return err
}

func ExecIPCommand(ctx context.Context, args ...string) ([]byte, error) {
	log.GetLogger(ctx).Info("Executing IP command: ip", args)
	cmd := exec.CommandContext(ctx,
		"ip",
		args...,
	)
	return cmd.CombinedOutput()
}

func SecondaryIPFromPrimaryIP(ctx context.Context, primaryIP string, index byte) (string, error) {
	primaryCidr := config.GetConfig(ctx).Lan.CIDR
	idx := strings.Index(primaryCidr, "/")
	if idx < 0 {
		return "", fmt.Errorf("invalid CIDR format: %s", primaryCidr)
	}
	suffix := primaryCidr[idx:]
	primaryIP += suffix
	cidr, err := CIDRForIndex(primaryIP, index)
	if err != nil {
		return "", fmt.Errorf("failed to get CIDR for primary IP %s and index %d: %w", primaryIP, index, err)
	}
	return strings.TrimSuffix(cidr, suffix), nil
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
	ip = ip.To4()
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

func IPForIndex(primary string, idx byte) (net.IP, *net.IPNet, error) {
	primaryCidr, primaryNet, err := net.ParseCIDR(primary)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid primary CIDR format: %w", err)
	}
	primaryCidr = primaryCidr.To4()
	size, _ := primaryNet.Mask.Size()
	ipByte := size/8 - 1
	lastSpecified := primaryCidr[ipByte]
	if ipByte == 0 {
		idx++ // on /8 we can't use 0 as the start byte
	}
	if idx >= lastSpecified {
		primaryCidr[ipByte] += idx
	} else {
		primaryCidr[ipByte] = idx
	}
	return primaryCidr, primaryNet, nil
}

func CIDRForIndex(primary string, idx byte) (string, error) {
	primaryIP, primaryNet, err := IPForIndex(primary, idx)
	if err != nil {
		return "", fmt.Errorf("failed to get IP for index %d: %w", idx, err)
	}
	size, _ := primaryNet.Mask.Size()
	return fmt.Sprintf("%s/%d", primaryIP.String(), size), nil
}
