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
}
