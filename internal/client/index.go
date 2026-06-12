//go:build windows

package client

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certRecord is a single entry from pki/index.txt.
type certRecord struct {
	Status    string // V=valid, R=revoked, E=expired
	ExpiresAt time.Time
	RevokedAt time.Time
	Serial    string
	CN        string
}

// readIndexTxt parses pki/index.txt and returns all cert records.
func readIndexTxt(pkiDir string) ([]certRecord, error) {
	f, err := os.Open(filepath.Join(pkiDir, "index.txt"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []certRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		r, ok := parseIndexLine(scanner.Text())
		if ok {
			records = append(records, r)
		}
	}
	return records, scanner.Err()
}

// parseIndexLine parses one line from index.txt.
//
// Format (tab-separated):
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

	exp, err := parseASN1Date(parts[1])
	if err == nil {
		r.ExpiresAt = exp
	}

	// Revoked records have an extra field at index 2.
	offset := 0
	if r.Status == "R" && len(parts) >= 6 {
		if rev, err := parseASN1Date(parts[2]); err == nil {
			r.RevokedAt = rev
		}
		offset = 1
	}

	if 3+offset < len(parts) {
		r.Serial = parts[3+offset]
	}
	if 5+offset < len(parts) {
		r.CN = extractCN(parts[5+offset])
	}

	return r, true
}

// parseASN1Date parses OpenSSL ASN.1 date: YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
func parseASN1Date(s string) (time.Time, error) {
	s = strings.TrimSuffix(s, "Z")
	switch len(s) {
	case 12:
		t, err := time.Parse("060102150405", s)
		if err != nil {
			return time.Time{}, err
		}
		// Two-digit year: 00-49 → 2000-2049, 50-99 → 1950-1999
		if t.Year() < 1970 {
			t = t.AddDate(100, 0, 0)
		}
		return t, nil
	case 14:
		return time.Parse("20060102150405", s)
	default:
		return time.Time{}, fmt.Errorf("unexpected date length %d: %q", len(s), s)
	}
}

// extractCN pulls the CN value from a subject string like /C=US/CN=laptop
func extractCN(subject string) string {
	for _, part := range strings.Split(subject, "/") {
		if after, ok := strings.CutPrefix(part, "CN="); ok {
			return after
		}
	}
	return subject
}
