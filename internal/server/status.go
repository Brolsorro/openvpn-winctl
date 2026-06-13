//go:build windows

// Package server provides OpenVPN server monitoring.
package server

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/config"
)

// Connection represents an active OpenVPN client session.
type Connection struct {
	CommonName  string
	RealAddr    string
	BytesRx     string
	BytesTx     string
	ConnectedAt string
}

// ShowConnections parses openvpn-status.log and prints active connections.
func ShowConnections(cfg *config.Config) error {
	statusFile := filepath.Join(cfg.LogsDir, "openvpn-status.log")
	f, err := os.Open(statusFile)
	if err != nil {
		return fmt.Errorf("open %s: %w\n(Is OpenVPN service running?)", statusFile, err)
	}
	defer f.Close()

	var conns []Connection
	inList := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Common Name,"):
			inList = true
		case strings.HasPrefix(line, "ROUTING TABLE"), strings.HasPrefix(line, "Global Stats"):
			inList = false
		case inList:
			// CommonName,RealAddress,BytesRx,BytesTx,ConnectedSince
			parts := strings.SplitN(line, ",", 5)
			if len(parts) == 5 {
				conns = append(conns, Connection{
					CommonName:  parts[0],
					RealAddr:    parts[1],
					BytesRx:     parts[2],
					BytesTx:     parts[3],
					ConnectedAt: parts[4],
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read status log: %w", err)
	}

	if len(conns) == 0 {
		fmt.Println("No active connections.")
		return nil
	}

	fmt.Printf("%-20s %-22s %-12s %-12s %s\n",
		"CLIENT", "REAL ADDRESS", "BYTES RX", "BYTES TX", "CONNECTED SINCE")
	fmt.Println(strings.Repeat("-", 85))
	for _, c := range conns {
		fmt.Printf("%-20s %-22s %-12s %-12s %s\n",
			c.CommonName, c.RealAddr, c.BytesRx, c.BytesTx, c.ConnectedAt)
	}
	fmt.Printf("\nTotal: %d connection(s)\n", len(conns))
	return nil
}

// ShowCertInfo prints info about a specific client cert from pki/index.txt.
func ShowCertInfo(cfg *config.Config, name string) error {
	records, err := readIndex(cfg.PkiDir)
	if err != nil {
		return err
	}
	found := false
	for _, r := range records {
		if r.CN != name {
			continue
		}
		found = true
		statusStr := map[string]string{"V": "VALID", "R": "REVOKED", "E": "EXPIRED"}[r.Status]
		fmt.Printf("Client     : %s\n", name)
		fmt.Printf("Status     : %s\n", statusStr)
		fmt.Printf("Serial     : %s\n", r.Serial)
		if !r.ExpiresAt.IsZero() {
			fmt.Printf("Expires    : %s\n", r.ExpiresAt.Format("2006-01-02"))
		}
		if r.Status == "R" && !r.RevokedAt.IsZero() {
			fmt.Printf("Revoked at : %s\n", r.RevokedAt.Format("2006-01-02 15:04:05"))
		}
		if r.Status == "V" {
			days := int(time.Until(r.ExpiresAt).Hours() / 24)
			if days < 30 {
				fmt.Printf("Expires in : %d days  *** EXPIRING SOON ***\n", days)
			} else {
				fmt.Printf("Expires in : %d days\n", days)
			}
		}
	}
	if !found {
		return fmt.Errorf("no certificate found for client %q", name)
	}
	return nil
}

// ShowExpiring prints valid certs expiring within <days>.
func ShowExpiring(cfg *config.Config, days int) error {
	records, err := readIndex(cfg.PkiDir)
	if err != nil {
		return err
	}
	threshold := time.Now().AddDate(0, 0, days)
	count := 0

	fmt.Printf("Certificates expiring within %d days:\n", days)
	fmt.Println(strings.Repeat("-", 55))
	for _, r := range records {
		if r.Status != "V" || r.ExpiresAt.After(threshold) {
			continue
		}
		daysLeft := int(time.Until(r.ExpiresAt).Hours() / 24)
		fmt.Printf("  %-25s expires %s (%d days)\n",
			r.CN, r.ExpiresAt.Format("2006-01-02"), daysLeft)
		count++
	}
	if count == 0 {
		fmt.Println("  None.")
	} else {
		fmt.Printf("\nTotal: %d expiring.\n", count)
	}
	return nil
}

// ShowRevoked prints all revoked certificates.
func ShowRevoked(cfg *config.Config) error {
	records, err := readIndex(cfg.PkiDir)
	if err != nil {
		return err
	}
	count := 0
	fmt.Println("Revoked certificates:")
	fmt.Println(strings.Repeat("-", 55))
	for _, r := range records {
		if r.Status != "R" {
			continue
		}
		fmt.Printf("  %-25s serial %-10s revoked %s\n",
			r.CN, r.Serial, r.RevokedAt.Format("2006-01-02 15:04:05"))
		count++
	}
	if count == 0 {
		fmt.Println("  None.")
	} else {
		fmt.Printf("\nTotal: %d revoked.\n", count)
	}
	return nil
}

// ──────────────────────────────────────────────
// index.txt parser

type certRecord struct {
	Status    string
	ExpiresAt time.Time
	RevokedAt time.Time
	Serial    string
	CN        string
}

func readIndex(pkiDir string) ([]certRecord, error) {
	f, err := os.Open(filepath.Join(pkiDir, "index.txt"))
	if err != nil {
		return nil, fmt.Errorf("open index.txt: %w", err)
	}
	defer f.Close()

	var records []certRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if r, ok := parseIndexLine(scanner.Text()); ok {
			records = append(records, r)
		}
	}
	return records, scanner.Err()
}

// parseIndexLine parses one tab-separated line from pki/index.txt.
//
//	Valid:   V  <expiry>           <serial>  unknown  <subject>
//	Revoked: R  <expiry>  <revoked>  <serial>  unknown  <subject>
func parseIndexLine(line string) (certRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return certRecord{}, false
	}
	parts := strings.Split(line, "\t")
	if len(parts) < 5 {
		return certRecord{}, false
	}

	r := certRecord{Status: parts[0]}
	if exp, err := parseASN1Date(parts[1]); err == nil {
		r.ExpiresAt = exp
	}

	offset := 0
	if r.Status == "R" && len(parts) >= 6 {
		if rev, err := parseASN1Date(parts[2]); err == nil {
			r.RevokedAt = rev
		}
		offset = 1
	}
	if i := 3 + offset; i < len(parts) {
		r.Serial = parts[i]
	}
	if i := 5 + offset; i < len(parts) {
		r.CN = extractCN(parts[i])
	}
	return r, true
}

// parseASN1Date parses YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ.
func parseASN1Date(s string) (time.Time, error) {
	s = strings.TrimSuffix(s, "Z")
	switch len(s) {
	case 12:
		t, err := time.Parse("060102150405", s)
		if err != nil {
			return time.Time{}, err
		}
		if t.Year() < 1970 {
			t = t.AddDate(100, 0, 0)
		}
		return t, nil
	case 14:
		return time.Parse("20060102150405", s)
	default:
		return time.Time{}, fmt.Errorf("unexpected date format: %q", s)
	}
}

func extractCN(subject string) string {
	for _, part := range strings.Split(subject, "/") {
		if after, ok := strings.CutPrefix(part, "CN="); ok {
			return after
		}
	}
	return subject
}
