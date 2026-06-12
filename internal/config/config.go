// Package config loads and validates manager configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Server holds OpenVPN server settings.
type Server struct {
	PublicIP        string   `yaml:"public_ip"`
	Port            int      `yaml:"port"`
	Proto           string   `yaml:"proto"`
	Network         string   `yaml:"network"`
	Netmask         string   `yaml:"netmask"`
	Topology        string   `yaml:"topology"`
	Cipher          string   `yaml:"cipher"`
	Auth            string   `yaml:"auth"`
	Keepalive       string   `yaml:"keepalive"`
	TLSCrypt        bool     `yaml:"tls_crypt"`
	Verb            int      `yaml:"verb"`
	FastIO          bool     `yaml:"fast_io"`
	SndBuf          int      `yaml:"snd_buf"`
	RcvBuf          int      `yaml:"rcv_buf"`
	ExtraPushRoutes []string `yaml:"extra_push_routes"`
}

// Client holds client generation settings.
type Client struct {
	InlineKeys bool `yaml:"inline_keys"`
}

// Backup holds backup settings.
type Backup struct {
	Enabled bool `yaml:"enabled"`
}

// Config is the root configuration structure.
type Config struct {
	OpenVPNRoot string `yaml:"openvpn_root"`
	Server      Server `yaml:"server"`
	Client      Client `yaml:"client"`
	Backup      Backup `yaml:"backup"`

	// Derived paths — computed from OpenVPNRoot, not in YAML.
	EasyRsaDir string
	ShExe      string
	BinDir     string
	ConfigDir  string
	ConfigAuto string
	ClientDir  string
	LogsDir    string
	BackupDir  string
	PkiDir     string
	TaKey      string
}

// Load reads config from cfgPath (or auto-discovers it) and returns a validated Config.
func Load(cfgPath string) (*Config, error) {
	if cfgPath == "" {
		cfgPath = discover()
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", cfgPath, err)
	}

	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.derive()
	return cfg, nil
}

// discover finds config.yaml by checking cwd first, then exe directory.
// This handles both `go run` (cwd) and compiled binary (next to exe).
func discover() string {
	candidates := func() []string {
		var paths []string
		if cwd, err := os.Getwd(); err == nil {
			paths = append(paths, filepath.Join(cwd, "config.yaml"))
		}
		if exe, err := os.Executable(); err == nil {
			if real, err := filepath.EvalSymlinks(exe); err == nil {
				exe = real
			}
			paths = append(paths, filepath.Join(filepath.Dir(exe), "config.yaml"))
		}
		return paths
	}()

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Return first candidate for a clear "file not found" error message.
	if len(candidates) > 0 {
		return candidates[0]
	}
	return "config.yaml"
}

func defaults() *Config {
	return &Config{
		OpenVPNRoot: `C:\Program Files\OpenVPN`,
		Server: Server{
			Port:      1194,
			Proto:     "udp4",
			Network:   "192.168.170.0",
			Netmask:   "255.255.255.0",
			Topology:  "subnet",
			Cipher:    "AES-256-GCM",
			Auth:      "SHA256",
			Keepalive: "10 60",
			TLSCrypt:  true,
			Verb:      3,
			FastIO:    true,
			SndBuf:    524288,
			RcvBuf:    524288,
		},
		Client: Client{InlineKeys: true},
		Backup: Backup{Enabled: true},
	}
}

func (c *Config) derive() {
	root := c.OpenVPNRoot
	c.EasyRsaDir = filepath.Join(root, "easy-rsa")
	c.ShExe      = filepath.Join(root, "easy-rsa", "bin", "sh.exe")
	c.BinDir     = filepath.Join(root, "easy-rsa", "bin")
	c.ConfigDir  = filepath.Join(root, "config")
	c.ConfigAuto = filepath.Join(root, "config-auto")
	c.ClientDir  = filepath.Join(root, "clients")
	c.LogsDir    = `C:\ProgramData\OpenVPN\logs`
	c.BackupDir  = filepath.Join(root, "pki-backups")
	c.PkiDir     = filepath.Join(root, "easy-rsa", "pki")
	c.TaKey      = filepath.Join(root, "config", "ta.key")
}
