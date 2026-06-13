//go:build windows

// Package system provides Windows service management and admin detection.
package system

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const ServiceName = "OpenVPNService"

// StartType represents the service startup type.
type StartType int

const (
	StartAutomatic StartType = iota
	StartManual
	StartDisabled
)

// Status returns the current service status string.
func Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "not installed", nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return "", err
	}

	cfg, _ := s.Config()
	startType := startTypeName(cfg.StartType)

	switch st.State {
	case svc.Running:
		return fmt.Sprintf("running  [startup: %s]", startType), nil
	case svc.Stopped:
		return fmt.Sprintf("stopped  [startup: %s]", startType), nil
	case svc.StartPending:
		return fmt.Sprintf("starting [startup: %s]", startType), nil
	case svc.StopPending:
		return fmt.Sprintf("stopping [startup: %s]", startType), nil
	default:
		return fmt.Sprintf("unknown(%d) [startup: %s]", st.State, startType), nil
	}
}

// Start starts the service.
func Start() error {
	return control("start")
}

// Stop stops the service.
func Stop() error {
	return control("stop")
}

// Restart stops then starts the service.
func Restart() error {
	_ = control("stop")
	time.Sleep(2 * time.Second)
	return control("start")
}

// SetAutoStart sets the service startup type.
//   - enabled=true  → Automatic (start with Windows)
//   - enabled=false → Manual    (start on demand)
func SetAutoStart(enabled bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	if enabled {
		cfg.StartType = mgr.StartAutomatic
		fmt.Printf("[service] %s set to automatic startup\n", ServiceName)
	} else {
		cfg.StartType = mgr.StartManual
		fmt.Printf("[service] %s set to manual startup\n", ServiceName)
	}

	return s.UpdateConfig(cfg)
}

// TailLog prints the last n lines of the log file and optionally
// follows new output (like tail -f) until ctx is cancelled.
func TailLog(ctx context.Context, logPath string, lines int, follow bool) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log %s: %w\n(Is OpenVPN service running?)", logPath, err)
	}
	defer f.Close()

	// Read existing content and print last N lines
	if err := printLastLines(f, lines); err != nil {
		return err
	}

	if !follow {
		return nil
	}

	// Follow mode: seek to end and watch for new content
	fmt.Printf("\n--- following %s (Ctrl+C to stop) ---\n", filepath.Base(logPath))
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
			// Reset scanner error for next poll
			if scanner.Err() != nil {
				scanner = bufio.NewScanner(f)
			}
		}
	}
}

// ──────────────────────────────────────────────
// helpers

func control(verb string) error {
	out, err := exec.Command("net", verb, ServiceName).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "already") {
			return nil
		}
		return fmt.Errorf("net %s %s: %w\n%s", verb, ServiceName, err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("[service] %s: %s\n", ServiceName, verb)
	return nil
}

func startTypeName(t uint32) string {
	switch t {
	case uint32(mgr.StartAutomatic):
		return "automatic"
	case uint32(mgr.StartManual):
		return "manual"
	case uint32(mgr.StartDisabled):
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// printLastLines prints the last n lines from a reader.
func printLastLines(r io.Reader, n int) error {
	scanner := bufio.NewScanner(r)
	var buf []string
	for scanner.Scan() {
		buf = append(buf, scanner.Text())
		if len(buf) > n {
			buf = buf[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, line := range buf {
		fmt.Println(line)
	}
	return nil
}

// IsAdmin reports whether the current process has administrator privileges.
func IsAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}