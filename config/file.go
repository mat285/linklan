package config

import (
	"context"
	"os"

	yaml "gopkg.in/yaml.v3"
)

func ReadFromFile(ctx context.Context, filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath) // Ensure the file exists and is readable
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config) // Unmarshal the YAML data into the Config struct
	if err != nil {
		return nil, err
	}
	err = config.Resolve(ctx) // Resolve the configuration, if necessary
	if err != nil {
		return nil, err
	}
	return &config, nil
}
