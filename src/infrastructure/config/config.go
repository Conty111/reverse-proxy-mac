package config

import (
	"encoding/json"
	"fmt"
	"os"

	"reverse-proxy-mac/src/domain/logger"
)

// Config represents the application configuration
type Config struct {
	Server ServerConfig `json:"server"`
	Log    LogConfig    `json:"log"`
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	GRPCPort int    `json:"grpc_port"`
	Host     string `json:"host"`
}

// LogConfig contains logging configuration
type LogConfig struct {
	Level      string `json:"level"`
	JSONFormat bool   `json:"json_format"`
}

// Load loads configuration from a JSON file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if cfg.Server.GRPCPort == 0 {
		cfg.Server.GRPCPort = 9001
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	return &cfg, nil
}

// GetLogLevel converts string log level to logger.Level
func (c *LogConfig) GetLogLevel() logger.Level {
	switch c.Level {
	case "debug":
		return logger.LevelDebug
	case "info":
		return logger.LevelInfo
	case "warn":
		return logger.LevelWarn
	case "error":
		return logger.LevelError
	default:
		return logger.LevelInfo
	}
}

