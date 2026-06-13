// Package config loads and validates manager configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RDPOptimizations holds network tuning settings for RDP-over-VPN performance.
// These settings disable compression, maximize buffers and tune MTU.
type RDPOptimizations struct {
	Enabled    bool `yaml:"enabled"`
	SndBuf     int  `yaml:"snd_buf"`   // socket send buffer, bytes
	RcvBuf     int  `yaml:"rcv_buf"`   // socket recv buffer, bytes
	TunMTU     int  `yaml:"tun_mtu"`   // tun interface MTU
	MSSFix     int  `yaml:"mssfix"`    // TCP MSS clamp
	FastIO     bool `yaml:"fast_io"`   // enable fast-io
}

// Server holds OpenVPN server settings.
type Server struct {
	PublicIP        string           `yaml:"public_ip"`
	Port            int              `yaml:"port"`
	Proto           string           `yaml:"proto"`
	Network         string           `yaml:"network"`
	Netmask         string           `yaml:"netmask"`
	Topology        string           `yaml:"topology"`
	Cipher          string           `yaml:"cipher"`
	DataCiphers     string           `yaml:"data_ciphers"`
	Auth            string           `yaml:"auth"`
	Keepalive       string           `yaml:"keepalive"`
	TLSCrypt        bool             `yaml:"tls_crypt"`
	Verb            int              `yaml:"verb"`
	AllowCompression bool            `yaml:"allow_compression"` // false = allow-compression no
	PushRoutes      []string         `yaml:"push_routes"`       // push "route ..." directives
	ExtraPushRoutes []string         `yaml:"extra_push_routes"` // anything else to push
	RDP             RDPOptimizations `yaml:"rdp"`
}

// Client holds client .ovpn generation settings.
type Client struct {
	InlineKeys  bool `yaml:"inline_keys"`
	RouteNoPull bool `yaml:"route_nopull"` // true = route-nopull + manual route; false = push route from server
	Verb        int  `yaml:"verb"`
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

// Load reads config from cfgPath (or auto-discovers it).
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

// discover finds config.yaml: cwd first, then exe directory.
// If config.yaml is not found but config.yaml.example exists,
// prints a helpful hint before returning the missing path.
func discover() string {
	dirs := func() []string {
		var out []string
		if cwd, err := os.Getwd(); err == nil {
			out = append(out, cwd)
		}
		if exe, err := os.Executable(); err == nil {
			if real, err := filepath.EvalSymlinks(exe); err == nil {
				exe = real
			}
			out = append(out, filepath.Dir(exe))
		}
		return out
	}()

	for _, dir := range dirs {
		p := filepath.Join(dir, "config.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// config.yaml not found — check for example file and hint the user
	for _, dir := range dirs {
		example := filepath.Join(dir, "config.yaml.example")
		if _, err := os.Stat(example); err == nil {
			fmt.Fprintf(os.Stderr,
				"hint: config.yaml not found. Copy the example and edit it:\n"+
				"  copy "%s" "%s"\n",
				example, filepath.Join(dir, "config.yaml"),
			)
			break
		}
	}

	if len(dirs) > 0 {
		return filepath.Join(dirs[0], "config.yaml")
	}
	return "config.yaml"
}

func defaults() *Config {
	return &Config{
		OpenVPNRoot: `C:\Program Files\OpenVPN`,
		Server: Server{
			Port:             1194,
			Proto:            "udp",
			Network:          "192.168.170.0",
			Netmask:          "255.255.255.0",
			Topology:         "subnet",
			Cipher:           "AES-128-GCM",
			DataCiphers:      "AES-128-GCM:CHACHA20-POLY1305",
			Auth:             "SHA256",
			Keepalive:        "10 60",
			TLSCrypt:         true,
			Verb:             2,
			AllowCompression: false,
			PushRoutes:       []string{"route 192.168.170.0 255.255.255.0"},
			RDP: RDPOptimizations{
				Enabled: true,
				SndBuf:  2097152,
				RcvBuf:  2097152,
				TunMTU:  1400,
				MSSFix:  1360,
				FastIO:  true,
			},
		},
		Client: Client{
			InlineKeys:  true,
			RouteNoPull: false, // server pushes routes by default
			Verb:        1,
		},
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
