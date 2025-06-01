package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mat285/linklan/discover"
	"github.com/mat285/linklan/link"
)

func main() {
	ctx := context.Background()
	if err := link.EnsureDirectLan(ctx, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error setting up direct LAN:", err)
		os.Exit(1)
	}

	localIP, err := link.FindPrimaryNetworkIP(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error finding primary network IP:", err)
		os.Exit(1)
	}

	peers, err := discover.GetActiveKubePeers(ctx, localIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error discovering active peers:", err)
		os.Exit(1)
	}

	if err := link.EnsureDirectLan(ctx, peers); err != nil {
		fmt.Fprintln(os.Stderr, "Error setting up direct LAN:", err)
		os.Exit(1)
	}

	fmt.Println("Direct LAN setup completed successfully")
	os.Exit(0)
}
