package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mat285/linklan/daemon"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	d := daemon.New()
	if err := d.Start(ctx); err != nil {
		os.Stderr.WriteString("Error starting daemon: " + err.Error() + "\n")
		os.Exit(1)
	}
}
