package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := defaults()
	if cfg.Server.Port != 1194 {
		t.Errorf("default Port = %d, want 1194", cfg.Server.Port)
	}
	if !cfg.Server.TLSCrypt {
		t.Error("default TLSCrypt should be true")
	}
	if !cfg.Backup.Enabled {
		t.Error("default Backup.Enabled should be true")
	}
	if !cfg.Client.InlineKeys {
		t.Error("default Client.InlineKeys should be true")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")

	yaml := `
openvpn_root: "C:\\OpenVPN"
server:
  port: 1195
  public_ip: "1.2.3.4"
`
	if err := os.WriteFile(cfgFile, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Server.Port != 1195 {
		t.Errorf("Port = %d, want 1195", cfg.Server.Port)
	}
	if cfg.Server.PublicIP != "1.2.3.4" {
		t.Errorf("PublicIP = %q, want 1.2.3.4", cfg.Server.PublicIP)
	}
	// Defaults not overridden should remain
	if cfg.Server.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher = %q, want AES-256-GCM", cfg.Server.Cipher)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestDerivePaths(t *testing.T) {
	cfg := defaults()
	cfg.OpenVPNRoot = `C:\OpenVPN`
	cfg.derive()

	if cfg.EasyRsaDir != `C:\OpenVPN\easy-rsa` {
		t.Errorf("EasyRsaDir = %q", cfg.EasyRsaDir)
	}
	if cfg.TaKey != `C:\OpenVPN\config\ta.key` {
		t.Errorf("TaKey = %q", cfg.TaKey)
	}
	if cfg.PkiDir != `C:\OpenVPN\easy-rsa\pki` {
		t.Errorf("PkiDir = %q", cfg.PkiDir)
	}
}
