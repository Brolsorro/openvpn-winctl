//go:build windows

// Package client manages OpenVPN client certificates and .ovpn configs.
package client

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/config"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/easyrsa"
)

//go:embed templates/client.ovpn.tmpl
var clientTmpl string

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Manager handles client certificate lifecycle.
type Manager struct {
	cfg *config.Config
	rs  *easyrsa.Runner
}

// New returns a client Manager.
func New(cfg *config.Config, rs *easyrsa.Runner) *Manager {
	return &Manager{cfg: cfg, rs: rs}
}

// Add creates a client certificate and .ovpn file.
// Stale PKI files from previous failed attempts are purged automatically.
func (m *Manager) Add(ctx context.Context, name string, withPassword bool) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := m.rs.BackupPKI(); err != nil {
		return err
	}

	// Remove leftovers from any failed previous attempt.
	// EasyRSA refuses to overwrite existing req/crt/key.
	m.purge(name)

	if err := m.rs.BuildClientFull(ctx, name, withPassword); err != nil {
		return fmt.Errorf("build-client-full: %w", err)
	}

	certFile := filepath.Join(m.cfg.PkiDir, "issued", name+".crt")
	keyFile  := filepath.Join(m.cfg.PkiDir, "private", name+".key")
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("expected PKI file not found: %s", f)
		}
	}

	return m.writeOVPN(name, certFile, keyFile)
}

// Revoke revokes a client certificate and purges all its files.
//
//   - If the certificate exists: easyrsa revoke → gen-crl → copy CRL → purge
//   - If the certificate is missing: skip easyrsa, purge remaining files
//
// Either way, no trace of the client remains after this call.
func (m *Manager) Revoke(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := m.rs.BackupPKI(); err != nil {
		return err
	}

	certFile := filepath.Join(m.cfg.PkiDir, "issued", name+".crt")
	certExists := fileExists(certFile)

	fmt.Printf("[client] Revoking %s...\n", name)

	if certExists {
		if err := m.rs.RunWithStdin(ctx, "revoke "+name, "yes\n"); err != nil {
			// Log warning but proceed with purge — partial state is worse.
			fmt.Printf("  [warn] easyrsa revoke: %v — purging files anyway\n", err)
		} else {
			if err := m.rs.Run(ctx, "gen-crl"); err != nil {
				fmt.Printf("  [warn] gen-crl: %v\n", err)
			} else {
				src := filepath.Join(m.cfg.PkiDir, "crl.pem")
				dst := filepath.Join(m.cfg.ConfigDir, "crl.pem")
				if err := copyFile(src, dst); err != nil {
					fmt.Printf("  [warn] copy crl.pem: %v\n", err)
				}
			}
		}
	} else {
		fmt.Printf("  [info] cert not found at %s — purging files only\n", certFile)
	}

	m.purge(name)

	if certExists {
		fmt.Printf("[client] %s revoked. Run: openvpn-manager service restart\n", name)
	} else {
		fmt.Printf("[client] %s purged (no cert to revoke).\n", name)
	}
	return nil
}

// Renew renews a client certificate (keeps same key, issues new cert).
func (m *Manager) Renew(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := m.rs.BackupPKI(); err != nil {
		return err
	}
	fmt.Printf("[client] Renewing certificate for %s...\n", name)
	if err := m.rs.Renew(ctx, name); err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	fmt.Println("[client] Certificate renewed. Rebuilding .ovpn...")
	certFile := filepath.Join(m.cfg.PkiDir, "issued", name+".crt")
	keyFile  := filepath.Join(m.cfg.PkiDir, "private", name+".key")
	return m.writeOVPN(name, certFile, keyFile)
}

// Clean removes all PKI and .ovpn files for a client without revoking.
// Use before re-creating a client that was partially created.
func (m *Manager) Clean(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	fmt.Printf("[client] Cleaning files for %q...\n", name)
	m.purge(name)
	fmt.Println("[client] Clean done.")
	return nil
}

// List prints client names that have a .ovpn file.
func (m *Manager) List() error {
	entries, err := os.ReadDir(m.cfg.ClientDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No clients directory found.")
			return nil
		}
		return err
	}
	fmt.Println("Clients:")
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".ovpn") {
			fmt.Printf("  %s\n", strings.TrimSuffix(e.Name(), ".ovpn"))
			count++
		}
	}
	if count == 0 {
		fmt.Println("  (none)")
	}
	return nil
}

// ListVerbose prints clients with certificate status and expiry info.
func (m *Manager) ListVerbose() error {
	records, err := readIndexTxt(m.cfg.PkiDir)
	if err != nil {
		return err
	}

	ovpnSet := make(map[string]bool)
	if entries, err := os.ReadDir(m.cfg.ClientDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".ovpn") {
				ovpnSet[strings.TrimSuffix(e.Name(), ".ovpn")] = true
			}
		}
	}

	fmt.Printf("%-20s %-10s %-12s %-6s %s\n", "NAME", "STATUS", "EXPIRES", "DAYS", "OVPN")
	fmt.Println(strings.Repeat("-", 55))

	count := 0
	for _, r := range records {
		if r.CN == "" || r.CN == "Easy-RSA CA" || r.CN == "server" {
			continue
		}
		status := map[string]string{"V": "valid", "R": "revoked", "E": "expired"}[r.Status]
		expStr, daysStr := "-", "-"
		if r.Status == "V" {
			expStr  = r.ExpiresAt.Format("2006-01-02")
			daysStr = fmt.Sprintf("%d", int(time.Until(r.ExpiresAt).Hours()/24))
		}
		ovpn := ""
		if ovpnSet[r.CN] {
			ovpn = "yes"
		}
		fmt.Printf("%-20s %-10s %-12s %-6s %s\n", r.CN, status, expStr, daysStr, ovpn)
		count++
	}
	if count == 0 {
		fmt.Println("  (none)")
	}
	return nil
}

// ──────────────────────────────────────────────
// .ovpn generation

type ovpnData struct {
	Name        string
	Timestamp   string
	Proto       string
	PublicIP    string
	Port        int
	Cipher      string
	DataCiphers string
	Network     string
	Netmask     string
	Verb        int
	RouteNoPull bool
	// RDP optimizations
	RDPEnabled bool
	SndBuf     int
	RcvBuf     int
	TunMTU     int
	MSSFix     int
}

func (m *Manager) writeOVPN(name, certFile, keyFile string) error {
	pubIP := m.cfg.Server.PublicIP
	if pubIP == "" {
		pubIP = detectPublicIP()
	}

	data := ovpnData{
		Name:        name,
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		Proto:       m.cfg.Server.Proto,
		PublicIP:    pubIP,
		Port:        m.cfg.Server.Port,
		Cipher:      m.cfg.Server.Cipher,
		DataCiphers: m.cfg.Server.DataCiphers,
		Network:     m.cfg.Server.Network,
		Netmask:     m.cfg.Server.Netmask,
		Verb:        m.cfg.Client.Verb,
		RouteNoPull: m.cfg.Client.RouteNoPull,
		RDPEnabled:  m.cfg.Server.RDP.Enabled,
		SndBuf:      m.cfg.Server.RDP.SndBuf,
		RcvBuf:      m.cfg.Server.RDP.RcvBuf,
		TunMTU:      m.cfg.Server.RDP.TunMTU,
		MSSFix:      m.cfg.Server.RDP.MSSFix,
	}

	tmpl, err := template.New("client").Parse(clientTmpl)
	if err != nil {
		return fmt.Errorf("parse client template: %w", err)
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return fmt.Errorf("render client template: %w", err)
	}
	conf := sb.String()

	if m.cfg.Client.InlineKeys {
		conf += buildInlineSection(m.cfg, certFile, keyFile)
	} else {
		conf += buildExternalSection(name, m.cfg)
	}

	if err := os.MkdirAll(m.cfg.ClientDir, 0o755); err != nil {
		return err
	}
	out := filepath.Join(m.cfg.ClientDir, name+".ovpn")
	if err := os.WriteFile(out, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("[client] Created: %s\n", out)
	return nil
}

func buildInlineSection(cfg *config.Config, certFile, keyFile string) string {
	ca   := readFile(filepath.Join(cfg.ConfigDir, "ca.crt"))
	ta   := readFile(cfg.TaKey)
	cert := readFile(certFile)
	key  := readFile(keyFile)

	var sb strings.Builder
	if cfg.Server.TLSCrypt {
		sb.WriteString("\n<tls-crypt>\n")
		sb.WriteString(ta)
		sb.WriteString("\n</tls-crypt>\n")
	} else {
		sb.WriteString("\nkey-direction 1\n<tls-auth>\n")
		sb.WriteString(ta)
		sb.WriteString("\n</tls-auth>\n")
	}
	sb.WriteString("\n<ca>\n")
	sb.WriteString(ca)
	sb.WriteString("\n</ca>\n<cert>\n")
	sb.WriteString(cert)
	sb.WriteString("\n</cert>\n<key>\n")
	sb.WriteString(key)
	sb.WriteString("\n</key>\n")
	return sb.String()
}

func buildExternalSection(name string, cfg *config.Config) string {
	tls := "tls-crypt ta.key"
	if !cfg.Server.TLSCrypt {
		tls = "tls-auth ta.key 1\nkey-direction 1"
	}
	return fmt.Sprintf("\n%s\nca ca.crt\ncert %s.crt\nkey %s.key\n", tls, name, name)
}

// ──────────────────────────────────────────────
// purge

// purge removes all PKI and .ovpn files for a client.
// Errors are logged as warnings — partial cleanup is acceptable.
func (m *Manager) purge(name string) {
	pki := m.cfg.PkiDir
	targets := []string{
		filepath.Join(pki, "reqs", name+".req"),
		filepath.Join(pki, "issued", name+".crt"),
		filepath.Join(pki, "private", name+".key"),
		filepath.Join(pki, "inline", name+".inline"),
		filepath.Join(pki, "inline", "private", name+".inline"),
		filepath.Join(m.cfg.ClientDir, name+".ovpn"),
	}
	for _, f := range targets {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			fmt.Printf("  [warn] remove %s: %v\n", f, err)
		} else if err == nil {
			fmt.Printf("  removed: %s\n", f)
		}
	}
}

// ──────────────────────────────────────────────
// helpers

func validateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid client name %q: use only letters, digits, hyphens, underscores", name)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("# ERROR: cannot read %s\n", path)
	}
	// Normalize line endings: 
 -> 

	// OpenVPN inline parser accepts both, but 
 is cleaner in .ovpn files
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.TrimRight(normalized, "\r\n")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func detectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		fmt.Println("  [warn] cannot detect public IP, using placeholder")
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))
	fmt.Printf("  detected public IP: %s\n", ip)
	return ip
}
