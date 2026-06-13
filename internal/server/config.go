//go:build windows

package server

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Brolsorro/ovpn-manager/internal/config"
)

//go:embed templates/server.ovpn.tmpl
var serverTmpl string

type serverData struct {
	Timestamp     string
	Port          int
	Proto         string
	ConfigDir     string
	TLSLine       string
	CRLLine       string
	NoCompression bool   // true = emit "allow-compression no"
	WindowsDriver string // empty on 2.7+ (deprecated)
	PersistKey    bool   // false on 2.7+ (deprecated, always on)
	Network       string
	Netmask         string
	Topology        string
	Cipher          string
	DataCiphers     string
	Auth            string
	Keepalive       string
	PushRoutes      []string
	ExtraPushRoutes []string
	StatusLog       string // path to openvpn-status.log
	Verb            int
	// RDP optimizations
	RDPEnabled bool
	FastIO     bool
	SndBuf     int
	RcvBuf     int
	TunMTU     int
	MSSFix     int
}

func buildServerData(cfg *config.Config) serverData {
	tlsLine := fmt.Sprintf(`tls-crypt "%s"`, filepath.ToSlash(cfg.TaKey))
	if !cfg.Server.TLSCrypt {
		tlsLine = fmt.Sprintf(`tls-auth "%s" 0`, filepath.ToSlash(cfg.TaKey))
	}

	// Include crl-verify only if crl.pem actually exists
	crlPath := filepath.Join(cfg.ConfigDir, "crl.pem")
	crlLine := ""
	if _, err := os.Stat(crlPath); err == nil {
		crlLine = fmt.Sprintf(`crl-verify "%s"`, filepath.ToSlash(crlPath))
	}

	// OpenVPN requires forward slashes or double backslashes in paths.
	// Forward slashes are simpler and officially supported on Windows.
	configDir := filepath.ToSlash(cfg.ConfigDir)
	logsDir   := filepath.ToSlash(cfg.LogsDir)

	return serverData{
		Timestamp:     time.Now().Format("2006-01-02 15:04:05"),
		Port:          cfg.Server.Port,
		Proto:         cfg.Server.Proto,
		ConfigDir:     configDir,
		TLSLine:       tlsLine,
		CRLLine:       crlLine,
		NoCompression: !cfg.Server.AllowCompression,
		// Deprecated in 2.7+: windows-driver and persist-key
		WindowsDriver: windowsDriver(cfg),
		PersistKey:    cfg.OpenVPNVersion < 27,
		Network:       cfg.Server.Network,
		Netmask:          cfg.Server.Netmask,
		Topology:         cfg.Server.Topology,
		Cipher:           cfg.Server.Cipher,
		DataCiphers:      cfg.Server.DataCiphers,
		Auth:             cfg.Server.Auth,
		Keepalive:        cfg.Server.Keepalive,
		PushRoutes:       cfg.Server.PushRoutes,
		ExtraPushRoutes:  cfg.Server.ExtraPushRoutes,
		StatusLog:        logsDir + "/openvpn-status.log",
		Verb:             cfg.Server.Verb,
		RDPEnabled:       cfg.Server.RDP.Enabled,
		FastIO:           cfg.Server.RDP.FastIO,
		SndBuf:           cfg.Server.RDP.SndBuf,
		RcvBuf:           cfg.Server.RDP.RcvBuf,
		TunMTU:           cfg.Server.RDP.TunMTU,
		MSSFix:           cfg.Server.RDP.MSSFix,
	}
}

// authValue returns empty string when auth is "none" or empty,
// so the template skips the auth directive entirely.
// With AEAD ciphers (GCM/CHACHA20), auth is built-in — explicit auth breaks DCO.
func authValue(a string) string {
	if a == "" || a == "none" {
		return ""
	}
	return a
}

// windowsDriver returns the windows-driver value for OpenVPN < 2.7.
// In 2.7+ the directive is deprecated — DCO is the default driver.
func windowsDriver(cfg *config.Config) string {
	if cfg.OpenVPNVersion >= 27 {
		return ""
	}
	return cfg.Server.WindowsDriver
}

// WriteConfig generates config-auto/server.ovpn from the embedded template.
// If the file already exists it is overwritten (use UpdateConfig for safe merge).
func WriteConfig(cfg *config.Config) error {
	return writeConfigTo(cfg, filepath.Join(cfg.ConfigAuto, "server.ovpn"))
}

// UpdateConfig safely updates server.ovpn:
//   - If no existing file → write fresh config
//   - If file exists → backup it, then write new config
//     Non-conflicting manual additions (comments, extra directives) are preserved
//     in the backup; the new file is authoritative from config.yaml.
//
// "Safe" here means: you never lose the previous working config —
// it's always in pki-backups/server_<timestamp>.ovpn before any change.
func UpdateConfig(cfg *config.Config) error {
	outPath := filepath.Join(cfg.ConfigAuto, "server.ovpn")

	if _, err := os.Stat(outPath); err == nil {
		// Backup existing config before overwriting
		if err := backupServerConfig(outPath, cfg.BackupDir); err != nil {
			return fmt.Errorf("backup existing config: %w", err)
		}
	}

	return writeConfigTo(cfg, outPath)
}

// EnsureCRLVerify appends crl-verify to server.ovpn if not already present.
// Called automatically after client revoke.
func EnsureCRLVerify(cfg *config.Config) error {
	path := filepath.Join(cfg.ConfigAuto, "server.ovpn")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read server.ovpn: %w", err)
	}
	if strings.Contains(string(data), "crl-verify") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	crlPath := filepath.ToSlash(filepath.Join(cfg.ConfigDir, "crl.pem"))
	_, err = fmt.Fprintf(f, "\ncrl-verify \"%s\"\n", crlPath)
	return err
}

// ──────────────────────────────────────────────
// internal

func writeConfigTo(cfg *config.Config, outPath string) error {
	// Register "not" function for template — Go templates don't have it built-in
	tmpl, err := template.New("server").Parse(serverTmpl)
	if err != nil {
		return fmt.Errorf("parse server template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, buildServerData(cfg)); err != nil {
		return fmt.Errorf("render server template: %w", err)
	}

	fmt.Printf("[config] Server config written: %s\n", outPath)
	return nil
}

func backupServerConfig(srcPath, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return err
	}
	ts := time.Now().Format("20060102_150405")
	dst := filepath.Join(backupDir, "server_"+ts+".ovpn")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("  [config] Previous server config backed up: %s\n", dst)
	return nil
}