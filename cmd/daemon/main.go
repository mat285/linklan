package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mat285/linklan/config"
	"github.com/mat285/linklan/daemon"
	"github.com/mat285/linklan/log"
)

func run() error {
	ctx := context.Background()
	cfg := config.Config{}
	configPath := "/etc/linklandaemon/config.yml"
	cmd := &cobra.Command{
		Use:           "run-api",
		Short:         "Run api server",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if configPath != "" {
				fromFile, err := config.ReadFromFile(ctx, configPath)
				if err != nil {
					if !os.IsNotExist(err) {
						os.Stderr.WriteString("Error loading config: " + err.Error() + "\n")
						os.Exit(1)
					}
					fromFile = &config.Config{}
				}
				cfg = *fromFile
			}
			ctx, err := cfg.Resolve(ctx)
			if err != nil {
				return err
			}

			log.GetLogger(ctx).Info("Using configuration:", cfg.String())

			ctx = config.WithConfig(ctx, cfg)

			d, err := daemon.New(ctx)
			if err != nil {
				return err
			}
			return d.Start(ctx)
		},
	}

	cmd.PersistentFlags().StringVarP(
		&configPath,
		"config-path",
		"c",
		configPath,
		"Path to a file where '.yml' configuration is stored; can be specified multiple times, last provided has highest precedence when merging",
	)

	return cmd.Execute()
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
