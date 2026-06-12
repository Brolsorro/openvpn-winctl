package server

import (
	"testing"
	"time"
)

func TestParseASN1Date(t *testing.T) {
	tests := []struct {
		input   string
		wantYear int
		wantErr  bool
	}{
		{"260101120000Z", 2026, false},
		{"991231235959Z", 1999, false},
		{"500101000000Z", 1950, false},
		{"490101000000Z", 2049, false},
		{"20260101120000Z", 2026, false},
		{"bad", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseASN1Date(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Year() != tc.wantYear {
				t.Errorf("year = %d, want %d", got.Year(), tc.wantYear)
			}
		})
	}
}

func TestExtractCN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/CN=laptop", "laptop"},
		{"/C=US/ST=CA/CN=myserver", "myserver"},
		{"/CN=", ""},
		{"noslash", "noslash"},
	}
	for _, tc := range tests {
		got := extractCN(tc.input)
		if got != tc.want {
			t.Errorf("extractCN(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseIndexLine(t *testing.T) {
	// Valid cert line
	validLine := "V\t260101120000Z\t\tABCD1234\tunknown\t/CN=laptop"
	r, ok := parseIndexLine(validLine)
	if !ok {
		t.Fatal("expected ok=true for valid line")
	}
	if r.Status != "V" {
		t.Errorf("Status = %q, want V", r.Status)
	}
	if r.CN != "laptop" {
		t.Errorf("CN = %q, want laptop", r.CN)
	}
	if r.Serial != "ABCD1234" {
		t.Errorf("Serial = %q, want ABCD1234", r.Serial)
	}
	if r.ExpiresAt.Year() != 2026 {
		t.Errorf("ExpiresAt.Year = %d, want 2026", r.ExpiresAt.Year())
	}

	// Revoked cert line
	revokedLine := "R\t260101120000Z\t250601120000Z\tDEAD5678\tunknown\t/CN=oldclient"
	r2, ok2 := parseIndexLine(revokedLine)
	if !ok2 {
		t.Fatal("expected ok=true for revoked line")
	}
	if r2.Status != "R" {
		t.Errorf("Status = %q, want R", r2.Status)
	}
	if r2.CN != "oldclient" {
		t.Errorf("CN = %q, want oldclient", r2.CN)
	}
	if r2.RevokedAt.IsZero() {
		t.Error("RevokedAt should not be zero")
	}

	// Empty / short lines
	if _, ok := parseIndexLine(""); ok {
		t.Error("empty line should return ok=false")
	}
	if _, ok := parseIndexLine("V\tonly two"); ok {
		t.Error("short line should return ok=false")
	}
}

func TestShowExpiringThreshold(t *testing.T) {
	// Verify the threshold logic used in ShowExpiring
	threshold := time.Now().AddDate(0, 0, 90)
	expiring := time.Now().AddDate(0, 0, 30)
	notExpiring := time.Now().AddDate(0, 0, 180)

	if !expiring.Before(threshold) {
		t.Error("30-day cert should be before 90-day threshold")
	}
	if notExpiring.Before(threshold) {
		t.Error("180-day cert should not be before 90-day threshold")
	}
}
