package link

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/mat285/linklan/log"
)

func SortInterfacesBySpeed(ifaces []string) ([]string, error) {
	speeds, err := InterfaceSpeeds(context.Background(), ifaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface speeds: %w", err)
	}
	sort.Slice(ifaces, func(i, j int) bool {
		speedI, okI := speeds[ifaces[i]]
		speedJ, okJ := speeds[ifaces[j]]
		if !okI || !okJ {
			return false // Keep original order if speed not found
		}
		if speedI == speedJ {
			return ifaces[i] < ifaces[j] // Sort by name if speeds are equal
		}
		return speedI > speedJ // Sort by speed descending
	})
	log.GetLogger(context.Background()).Info("Sorted interfaces by speed:", ifaces)
	return ifaces, nil
}

func InterfaceSpeeds(ctx context.Context, ifaces []string) (map[string]int, error) {
	if len(ifaces) == 0 {
		return nil, nil
	}

	speeds := make(map[string]int)
	for _, iface := range ifaces {
		speed, err := InterfaceSpeed(ctx, iface)
		if err != nil {
			return nil, err
		}
		if speed < 0 {
			continue
		}
		speeds[iface] = speed
	}

	return speeds, nil
}

func InterfaceSpeed(ctx context.Context, iface string) (int, error) {
	cmd := exec.CommandContext(ctx, "ethtool", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return -1, err
	}
	marker := "Speed:"
	idx := strings.Index(string(output), marker)
	if idx < 0 {
		return -1, nil // Speed not found
	}
	start := idx + len(marker)
	end := strings.Index(string(output)[start:], "\n")
	if end < 0 {
		end = len(output)
	} else {
		end += start
	}
	speedStr := strings.TrimSpace(string(output)[start:end])
	speedStr = strings.TrimSuffix(speedStr, "Mb/s") // Remove unit if present
	var speed int
	_, err = fmt.Sscanf(speedStr, "%d", &speed)
	if err != nil {
		return -1, fmt.Errorf("failed to parse speed for interface %s: %w", iface, err)
	}
	if speed <= 0 {
		return -1, nil // Invalid speed
	}
	log.GetLogger(ctx).Info("Interface speed for", iface, "is", speed, "Mb/s")
	return speed, nil
}
