// Package config handles loading and validating the YAML bootstrap
// configuration for MSNGR, including environment variable expansion and defaults.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the minimal YAML bootstrap configuration.
// All dynamic configuration (accounts, rules, policies) lives in SQLite.
type Config struct {
	Listen        string           `yaml:"listen"`
	DB            DBConfig         `yaml:"db"`
	StoragePath   string           `yaml:"storage_path"`
	EncryptionKey string           `yaml:"encryption_key"`
	Log           LogConfig        `yaml:"log"`
	Ticks         TickConfig       `yaml:"ticks"`
	HardPolicy    HardPolicyConfig `yaml:"hard_policy"`
	Session       SessionConfig    `yaml:"session"`
}

// SessionConfig holds timeout settings for MCP agent and operator sessions.
type SessionConfig struct {
	MCPTimeoutMinutes      int `yaml:"mcp_timeout_minutes"`
	OperatorTimeoutMinutes int `yaml:"operator_timeout_minutes"`
}

// HardPolicyConfig defines the safety limits enforced by the config policy layer,
// including message size caps, recipient limits, and blocked domains/extensions.
type HardPolicyConfig struct {
	MaxMessageSizeMB    int      `yaml:"max_message_size_mb"`
	MaxRecipients       int      `yaml:"max_recipients"`
	DenyDomains         []string `yaml:"deny_domains"`
	ForbiddenExtensions []string `yaml:"forbidden_extensions"`
}

// DBConfig specifies the SQLite database path.
type DBConfig struct {
	Path string `yaml:"path"`
}

// LogConfig holds the logging level setting.
type LogConfig struct {
	Level string `yaml:"level"`
}

// TickConfig controls the polling intervals for IMAP retrieval, outbound queue
// processing, and maintenance tasks, all specified in milliseconds.
type TickConfig struct {
	IMAPPollMs     int `yaml:"imap_poll_ms"`
	QueueProcessMs int `yaml:"queue_process_ms"`
	MaintenanceMs  int `yaml:"maintenance_ms"`
}

// Load reads a YAML config file, expands ${ENV_VAR} references, and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	expanded := expandEnvVars(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(cfg)
	return cfg, nil
}

var envVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnvVars(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "${"), "}")
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return match
	})
}

func applyDefaults(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = ":8600"
	}
	if cfg.DB.Path == "" {
		cfg.DB.Path = "./msngr.db"
	}
	if cfg.StoragePath == "" {
		cfg.StoragePath = "./storage"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Ticks.IMAPPollMs <= 0 {
		cfg.Ticks.IMAPPollMs = 30000
	}
	if cfg.Ticks.QueueProcessMs <= 0 {
		cfg.Ticks.QueueProcessMs = 10000
	}
	if cfg.Ticks.MaintenanceMs <= 0 {
		cfg.Ticks.MaintenanceMs = 300000
	}
	if cfg.HardPolicy.MaxMessageSizeMB <= 0 {
		cfg.HardPolicy.MaxMessageSizeMB = 25
	}
	if cfg.HardPolicy.MaxRecipients <= 0 {
		cfg.HardPolicy.MaxRecipients = 50
	}
	if cfg.Session.MCPTimeoutMinutes <= 0 {
		cfg.Session.MCPTimeoutMinutes = 60
	}
	if cfg.Session.OperatorTimeoutMinutes <= 0 {
		cfg.Session.OperatorTimeoutMinutes = 1440
	}
	if len(cfg.HardPolicy.ForbiddenExtensions) == 0 {
		cfg.HardPolicy.ForbiddenExtensions = []string{
			".exe", ".bat", ".cmd", ".scr", ".pif",
			".com", ".vbs", ".js", ".wsf", ".msi",
		}
	}
}
