package link

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mat285/linklan/log"
)

const (
	PrimaryLanIpPrefix = "192.168.1."

	SecondaryInterfacePrefix = "enx"
	SecondaryLanIpPrefix     = "192.168.0."
	SecondaryLanCidr         = SecondaryLanIpPrefix + "0/24"

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
	iface := ifaces[0]
	if len(ifaces) > 1 {
		return HandleBondedInterfaces(ctx, primaryIP, ifaces)
	}

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
		if iface == BondInterfaceName {
			for _, i := range ifaces {
				if i == iface {
					continue // Skip the bond interface itself
				}
				if err := SetInterfaceUp(ctx, i); err != nil {
					return fmt.Errorf("failed to set interface %s up: %w", i, err)
				}
			}
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
		if err := SetInterfaceUp(ctx, BondInterfaceName); err != nil {
			return fmt.Errorf("failed to set bonded interface: %w", err)
		}
	}
	log.Default().Info("All interfaces are bonded to", BondInterfaceName)

	for _, i := range ifaces {
		if i == BondInterfaceName {
			continue // Skip the bond interface itself
		}
		if err := SetInterfaceUp(ctx, i); err != nil {
			return fmt.Errorf("failed to set interface %s up: %w", i, err)
		}
	}

	assigned, err := CheckSecondaryLanIp(ctx, BondInterfaceName, primaryIP)
	if err != nil {
		return fmt.Errorf("failed to check secondary LAN IP: %w", err)
	}
	if !assigned {
		if err := SetInterfaceDown(ctx, BondInterfaceName); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
		for _, i := range ifaces {
			log.Default().Info("Setting interface", i, "down and up to ensure it is ready")
			// Ensure all interfaces are down and up to apply changes
			if err := SetInterfaceDown(ctx, i); err != nil {
				return fmt.Errorf("failed to set interface down: %w", err)
			}
		}
		if err := SetInterfaceUp(ctx, BondInterfaceName); err != nil {
			return fmt.Errorf("failed to set interface up: %w", err)
		}
		for _, i := range ifaces {
			log.Default().Info("Setting interface", i, "up and up to ensure it is ready")
			if err := SetInterfaceUp(ctx, i); err != nil {
				return fmt.Errorf("failed to set interface up: %w", err)
			}
		}
		if err := AssignSecondaryLanIp(ctx, BondInterfaceName, primaryIP); err != nil {
			return fmt.Errorf("failed to assign lan ip: %w", err)
		}
	}
	if err := AssignSecondaryLanCidrRoute(ctx, BondInterfaceName); err != nil {
		return fmt.Errorf("failed to assign lan routes: %w", err)
	}
	return nil
}

func EnsureBondInterface(ctx context.Context) error {
	log.Default().Info("Ensuring bond interface is set up")
	output, err := ExecIPCommand(ctx, "link", "show", BondInterfaceName) // Clean up any existing bond
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
	outputBytes, err := ExecIPCommand(ctx, "link", "list")
	if err != nil {
		return nil, err
	}
	output := string(outputBytes)
	ifaces := []string{}
	idx := strings.Index(output, SecondaryInterfacePrefix)
	for idx > 0 && idx <= len(output) {
		output = output[idx:]
		end := strings.Index(output, ":")
		if end < 0 {
			break
		}
		iface := strings.TrimSpace(output[:end])
		ifaces = append(ifaces, strings.TrimSpace(iface))
		output = output[end+1:]
		idx = strings.Index(output, SecondaryInterfacePrefix)
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no secondary network interfaces found")
	}
	log.Default().Info("Found secondary network interfaces:", ifaces)
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
	log.Default().Info("Checking if secondary LAN IP is assigned to interface:", interfaceName)
	secondaryIP := SecondaryIPFromPrimaryIP(primaryIP)
	existing, err := FindSecondaryNetworkIP(ctx, interfaceName)
	if err != nil {
		if err.Error() == "no network IP found" {
			log.Default().Info("No secondary IP found for interface", interfaceName, "assuming it is not assigned")
			return false, nil
		}
		return false, err
	}
	log.Default().Info("Found existing secondary IP:", existing, "for interface", interfaceName)
	return existing == secondaryIP, nil
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
	_, err := ExecIPCommand(ctx, "route", "show", "dev", iface)
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
	// log.Default().Info("Executing IP command:", args)
	cmd := exec.CommandContext(ctx,
		"ip",
		args...,
	// append([]string{"ip"}, args...)...,
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
