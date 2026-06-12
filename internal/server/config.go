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
	Timestamp  string
	Port       int
	Proto      string
	ConfigDir  string
	TLSLine    string
	Network    string
	Netmask    string
	Topology   string
	Cipher     string
	Auth       string
	Keepalive  string
	FastIO     bool
	SndBuf     int
	RcvBuf     int
	LogsDir    string
	Verb       int
	PushRoutes string
}

// WriteConfig generates config-auto/server.ovpn from the embedded template.
func WriteConfig(cfg *config.Config) error {
	tlsLine := fmt.Sprintf(`tls-crypt "%s"`, cfg.TaKey)
	if !cfg.Server.TLSCrypt {
		tlsLine = fmt.Sprintf(`tls-auth "%s" 0`, cfg.TaKey)
	}

	pushRoutes := ""
	if len(cfg.Server.ExtraPushRoutes) > 0 {
		lines := make([]string, len(cfg.Server.ExtraPushRoutes))
		for i, r := range cfg.Server.ExtraPushRoutes {
			lines[i] = fmt.Sprintf(`push "%s"`, r)
		}
		pushRoutes = strings.Join(lines, "\n")
	}

	data := serverData{
		Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
		Port:       cfg.Server.Port,
		Proto:      cfg.Server.Proto,
		ConfigDir:  cfg.ConfigDir,
		TLSLine:    tlsLine,
		Network:    cfg.Server.Network,
		Netmask:    cfg.Server.Netmask,
		Topology:   cfg.Server.Topology,
		Cipher:     cfg.Server.Cipher,
		Auth:       cfg.Server.Auth,
		Keepalive:  cfg.Server.Keepalive,
		FastIO:     cfg.Server.FastIO,
		SndBuf:     cfg.Server.SndBuf,
		RcvBuf:     cfg.Server.RcvBuf,
		LogsDir:    cfg.LogsDir,
		Verb:       cfg.Server.Verb,
		PushRoutes: pushRoutes,
	}

	tmpl, err := template.New("server").Parse(serverTmpl)
	if err != nil {
		return fmt.Errorf("parse server template: %w", err)
	}

	outPath := filepath.Join(cfg.ConfigAuto, "server.ovpn")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render server template: %w", err)
	}

	fmt.Printf("[config] Server config written: %s\n", outPath)
	return nil
}

// EnsureCRLVerify appends crl-verify to server.ovpn if not already present.
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
	_, err = fmt.Fprintf(f, "\ncrl-verify \"%s\\crl.pem\"\n", cfg.ConfigDir)
	return err
}
