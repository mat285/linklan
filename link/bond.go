package link

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mat285/linklan/log"
)

func HandleBondedInterfaces(ctx context.Context, primaryIP string, ifaces []string) error {
	log.GetLogger(ctx).Info("Multiple secondary interfaces found, ensuring bond interface is set up")
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
	log.GetLogger(ctx).Info("All interfaces are bonded to", BondInterfaceName)
	return nil
}

func EnsureBondInterface(ctx context.Context) error {
	log.GetLogger(ctx).Info("Ensuring bond interface is set up")
	if err := exec.CommandContext(ctx, "modprobe", "bonding").Run(); err != nil {
		return fmt.Errorf("failed to load bonding module: %w", err)
	}
	output, err := ExecIPCommand(ctx, "link", "show") // Clean up any existing bond
	if err != nil {
		return fmt.Errorf("failed to check existing bond interface: %w", err)
	}
	if strings.Contains(string(output), BondInterfaceName) {
		log.GetLogger(ctx).Info("Bond interface bond0 already exists")
		return nil // Bond interface already exists, no need to create it
	}

	log.GetLogger(ctx).Info("Creating new bond interface bond0 with mode 802.3ad")
	args := []string{"link", "add", BondInterfaceName, "type", "bond", "mode", "802.3ad"}
	if _, err := ExecIPCommand(ctx, args...); err != nil {
		return fmt.Errorf("failed to create bond interface: %w", err)
	} // Create new bond interface
	log.GetLogger(ctx).Info("Successfully ensured bond interface is set up")
	return nil
}

func UnbondedInterfaces(ctx context.Context, ifaces []string) ([]string, error) {
	unbound := []string{}
	for _, iface := range ifaces {
		log.GetLogger(ctx).Info("Checking if interface", iface, "is unbonded")
		output, err := ExecIPCommand(ctx, "link", "show", iface)
		if err != nil {
			return nil, fmt.Errorf("failed to check interface %s: %w", iface, err)
		}
		if strings.Contains(string(output), "master "+BondInterfaceName) {
			log.GetLogger(ctx).Info("Interface", iface, "is bonded ", BondInterfaceName)
			continue
		}
		log.GetLogger(ctx).Info("Interface", iface, "is unbonded")
		unbound = append(unbound, iface)
	}
	return unbound, nil
}

func RemoveBondInterfaces(ctx context.Context, ifaces []string) error {
	log.GetLogger(ctx).Info("Removing bond from secondary interfaces:", ifaces)
	if len(ifaces) == 0 {
		return fmt.Errorf("no interfaces to unbond")
	}
	for _, iface := range ifaces {
		log.GetLogger(ctx).Info("Removing interface", iface, "from bond0")
		if _, err := ExecIPCommand(ctx, "link", "set", iface, "nomaster"); err != nil {
			return fmt.Errorf("failed to remove interface %s from bond: %w", iface, err)
		}
		if err := SetInterfaceDown(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
	}
	log.GetLogger(ctx).Info("Successfully removed bond from interfaces:", ifaces)
	return nil
}

func BondInterfaces(ctx context.Context, ifaces []string) error {
	log.GetLogger(ctx).Info("Bonding secondary interfaces:", ifaces)
	if len(ifaces) == 0 {
		return fmt.Errorf("no interfaces to bond")
	}
	for _, iface := range ifaces {
		if err := SetInterfaceDown(ctx, iface); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
		log.GetLogger(ctx).Info("Adding interface", iface, "to bond0")
		if _, err := ExecIPCommand(ctx, "link", "set", iface, "master", BondInterfaceName); err != nil {
			return fmt.Errorf("failed to add interface %s to bond: %w", iface, err)
		}
	}
	log.GetLogger(ctx).Info("Successfully bonded interfaces:", ifaces)
	return nil
}
