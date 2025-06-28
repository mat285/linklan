package config

import "context"

type configKey struct{}

func WithConfig(ctx context.Context, config Config) context.Context {
	return context.WithValue(ctx, configKey{}, config)
}

func GetConfig(ctx context.Context) *Config {
	raw := ctx.Value(configKey{})
	config, ok := raw.(Config)
	if !ok {
		return nil
	}

	return &config
}
