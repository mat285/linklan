package main

import (
	"fmt"
	"net"
)

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting network interfaces:", err)
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error getting addresses for interface", iface.Name, ":", err)
		}
		for _, addr := range addrs {
			fmt.Println("Interface:", iface.Name, "Address:", addr.String())
		}
	}
	// ctx := context.Background()
	// if err := link.EnsureDirectLan(ctx, nil); err != nil {
	// 	fmt.Fprintln(os.Stderr, "Error setting up direct LAN:", err)
	// 	os.Exit(1)
	// }

	// localIP, err := link.FindPrimaryNetworkIP(ctx)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, "Error finding primary network IP:", err)
	// 	os.Exit(1)
	// }

	// peers, err := discover.GetActiveKubePeers(ctx, localIP)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, "Error discovering active peers:", err)
	// 	os.Exit(1)
	// }

	// if err := link.EnsureDirectLan(ctx, peers); err != nil {
	// 	fmt.Fprintln(os.Stderr, "Error setting up direct LAN:", err)
	// 	os.Exit(1)
	// }

	// log.GetLogger(ctx).Info("Direct LAN setup completed successfully")
	// os.Exit(0)
}
