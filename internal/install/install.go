//go:build windows

// Package install handles OpenVPN MSI installation and version detection.
package install

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Brolsorro/ovpn-manager/internal/config"
)

const (
	Version = "1.0.0"

	msiURLX64 = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.12-I001-amd64.msi"
	msiURLX86 = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.12-I001-x86.msi"
)

// Versions holds installed component versions.
type Versions struct {
	Manager  string
	OpenVPN  string
	EasyRSA  string
	Platform string
}

// Get returns installed component versions.
func Get(cfg *config.Config) Versions {
	v := Versions{
		Manager:  Version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	ovpnBin := filepath.Join(cfg.OpenVPNRoot, "bin", "openvpn.exe")
	if out, err := exec.Command(ovpnBin, "--version").Output(); err == nil {
		if lines := strings.SplitN(string(out), "\n", 2); len(lines) > 0 {
			v.OpenVPN = strings.TrimSpace(lines[0])
		}
	} else {
		v.OpenVPN = "not installed"
	}

	v.EasyRSA = easyrsaVersion(cfg.EasyRsaDir)
	return v
}

// Print prints component versions to stdout.
func Print(cfg *config.Config) {
	v := Get(cfg)
	fmt.Printf("Manager  : %s\n", v.Manager)
	fmt.Printf("OpenVPN  : %s\n", v.OpenVPN)
	fmt.Printf("EasyRSA  : %s\n", v.EasyRSA)
	fmt.Printf("Platform : %s\n", v.Platform)
}

// Install downloads and installs OpenVPN MSI.
// Skips if already installed.
func Install(cfg *config.Config) error {
	ovpnBin := filepath.Join(cfg.OpenVPNRoot, "bin", "openvpn.exe")
	if _, err := os.Stat(ovpnBin); err == nil {
		fmt.Println("OpenVPN is already installed.")
		Print(cfg)
		return nil
	}

	msiURL := msiURLX64
	if runtime.GOARCH == "386" {
		msiURL = msiURLX86
	}

	msiPath := filepath.Join(os.TempDir(), "openvpn-install.msi")
	fmt.Printf("Downloading OpenVPN installer...\n  %s\n", msiURL)
	if err := downloadFile(msiURL, msiPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer os.Remove(msiPath)

	fmt.Println("Installing (this may take a minute)...")
	cmd := exec.Command("msiexec.exe",
		"/i", msiPath, "/passive",
		"ADDLOCAL=OpenVPN.GUI,OpenVPN.Service,OpenVPN.OpenVPN,OpenVPN.EasyRSA",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("msiexec: %w", err)
	}
	fmt.Println("OpenVPN installed.")
	return nil
}

// Uninstall removes PKI data and configs. Optionally removes the MSI.
func Uninstall(cfg *config.Config, removeMSI bool) error {
	dirs := []string{cfg.PkiDir, cfg.ConfigDir, cfg.ConfigAuto, cfg.ClientDir, cfg.BackupDir}
	fmt.Println("Removing PKI and config directories...")
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil && !os.IsNotExist(err) {
			fmt.Printf("  [warn] remove %s: %v\n", d, err)
		} else if err == nil {
			fmt.Printf("  removed: %s\n", d)
		}
	}
	if removeMSI {
		fmt.Println("Uninstalling OpenVPN MSI...")
		cmd := exec.Command("msiexec.exe", "/x", "OpenVPN", "/passive")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  [warn] MSI uninstall: %v\n  Use Control Panel if needed.\n", err)
		}
	}
	fmt.Println("Done.")
	return nil
}

// ──────────────────────────────────────────────
// helpers

func easyrsaVersion(easyrsaDir string) string {
	data, err := os.ReadFile(filepath.Join(easyrsaDir, "easyrsa"))
	if err != nil {
		return "not found"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, `EASYRSA_version="`); ok {
			return strings.TrimSuffix(after, `"`)
		}
		if after, ok := strings.CutPrefix(line, "EASYRSA_version="); ok {
			return strings.Trim(after, `"'`)
		}
	}
	return "unknown"
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}
