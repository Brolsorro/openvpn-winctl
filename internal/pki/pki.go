//go:build windows

// Package pki manages OpenVPN PKI lifecycle via EasyRSA.
package pki

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/config"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/easyrsa"
)

// Manager handles PKI initialization and maintenance.
type Manager struct {
	cfg *config.Config
	rs  *easyrsa.Runner
}

// New returns a PKI Manager.
func New(cfg *config.Config, rs *easyrsa.Runner) *Manager {
	return &Manager{cfg: cfg, rs: rs}
}

// Init initializes a new PKI.
//
//   - withCAPassword: prompt for CA key passphrase (hidden input)
//
// WARNING: this destroys the existing PKI directory and all certificates.
func (m *Manager) Init(ctx context.Context, withCAPassword bool) error {
	for _, d := range []string{m.cfg.ConfigDir, m.cfg.ConfigAuto, m.cfg.ClientDir, m.cfg.LogsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	if err := m.rs.Run(ctx, "init-pki"); err != nil {
		return fmt.Errorf("init-pki: %w", err)
	}

	fmt.Println("[pki] build-ca...")
	if err := m.rs.BuildCA(ctx, withCAPassword); err != nil {
		return fmt.Errorf("build-ca: %w", err)
	}

	for _, step := range []string{"gen-dh", "build-server-full server nopass", "gen-crl"} {
		fmt.Printf("[pki] %s...\n", step)
		if err := m.rs.Run(ctx, step); err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
	}

	fmt.Println("[pki] Generating ta.key...")
	if err := m.genTAKey(); err != nil {
		return err
	}

	if err := m.SyncConfigDir(); err != nil {
		return err
	}

	fmt.Println("[pki] Initialization complete.")
	return nil
}

// SyncCRL regenerates CRL and copies it to config dir.
// Safe — does not touch keys or certificates.
func (m *Manager) SyncCRL(ctx context.Context) error {
	fmt.Println("[pki] Regenerating CRL...")
	if err := m.rs.Run(ctx, "gen-crl"); err != nil {
		return fmt.Errorf("gen-crl: %w", err)
	}
	src := filepath.Join(m.cfg.PkiDir, "crl.pem")
	dst := filepath.Join(m.cfg.ConfigDir, "crl.pem")
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy crl.pem: %w", err)
	}
	fmt.Printf("[pki] CRL updated: %s\n", dst)
	return nil
}

// SyncConfigDir copies PKI output files to config dir without modifying PKI.
// Copies: ca.crt, dh.pem, server.crt, server.key, crl.pem
func (m *Manager) SyncConfigDir() error {
	pki := m.cfg.PkiDir
	pairs := [][2]string{
		{filepath.Join(pki, "ca.crt"), filepath.Join(m.cfg.ConfigDir, "ca.crt")},
		{filepath.Join(pki, "dh.pem"), filepath.Join(m.cfg.ConfigDir, "dh.pem")},
		{filepath.Join(pki, "issued", "server.crt"), filepath.Join(m.cfg.ConfigDir, "server.crt")},
		{filepath.Join(pki, "private", "server.key"), filepath.Join(m.cfg.ConfigDir, "server.key")},
		{filepath.Join(pki, "crl.pem"), filepath.Join(m.cfg.ConfigDir, "crl.pem")},
	}
	for _, p := range pairs {
		if err := copyFile(p[0], p[1]); err != nil {
			return fmt.Errorf("sync %s: %w", filepath.Base(p[0]), err)
		}
		fmt.Printf("  synced: %s\n", filepath.Base(p[1]))
	}
	return nil
}

// Backup creates a timestamped copy of the PKI directory.
func (m *Manager) Backup() error {
	return m.rs.BackupPKI()
}

// genTAKey generates ta.key via openvpn --genkey.
func (m *Manager) genTAKey() error {
	ovpnBin := filepath.Join(m.cfg.OpenVPNRoot, "bin", "openvpn.exe")
	cmd := exec.Command(ovpnBin, "--genkey", "secret", m.cfg.TaKey)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openvpn --genkey: %w", err)
	}
	if _, err := os.Stat(m.cfg.TaKey); err != nil {
		return fmt.Errorf("ta.key not created at %s", m.cfg.TaKey)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
