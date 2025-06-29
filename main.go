package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	addr := net.JoinHostPort("0.0.0.0", "12345")
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		fmt.Println("Error listening on UDP port:", err)
		return
	}
	defer conn.Close()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Shutting down UDP listener")
				return
			default:
			}
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				fmt.Println("Error reading from UDP:", err)
				continue
			}
			fmt.Printf("Received %d bytes from %s: %s\n", n, raddr, string(buf[:n]))
			fmt.Println(string(buf[:n]))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Context done, exiting goroutine")
				return
			case <-time.After(1 * time.Second):
			}
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP:   net.IPv4bcast,
				Port: 12345,
			})
			if err != nil {
				fmt.Println("Error dialing UDP broadcast address:", err)
				continue
			}
			n, err := conn.Write([]byte("Hello from UDP listener!"))
			fmt.Println("Sent", n, "bytes", err)
			conn.Close()
		}
	}()

	wg.Wait()

	// ifaces, err := net.Interfaces()
	// if err != nil {
	// 	fmt.Println("Error getting network interfaces:", err)
	// 	return
	// }

	// for _, iface := range ifaces {
	// 	addrs, err := iface.Addrs()
	// 	if err != nil {
	// 		fmt.Println("Error getting addresses for interface", iface.Name, ":", err)
	// 	}
	// 	for _, addr := range addrs {
	// 		fmt.Println("Interface:", iface.Name, "Address:", addr.String())
	// 	}
	// }
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
