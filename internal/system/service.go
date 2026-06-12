//go:build windows

// Package system provides Windows service management and admin detection.
package system

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const ServiceName = "OpenVPNService"

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
	switch st.State {
	case svc.Running:
		return "running", nil
	case svc.Stopped:
		return "stopped", nil
	case svc.StartPending:
		return "starting", nil
	case svc.StopPending:
		return "stopping", nil
	default:
		return fmt.Sprintf("unknown(%d)", st.State), nil
	}
}

// Start starts the service and sets it to auto-start.
func Start() error {
	if err := setAutoStart(); err != nil {
		fmt.Printf("[service] [warn] set auto-start: %v\n", err)
	}
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

func control(verb string) error {
	out, err := exec.Command("net", verb, ServiceName).CombinedOutput()
	if err != nil {
		// "already running" / "already stopped" are not errors.
		if strings.Contains(string(out), "already") {
			return nil
		}
		return fmt.Errorf("net %s %s: %w\n%s", verb, ServiceName, err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("[service] %s: %s\n", ServiceName, verb)
	return nil
}

func setAutoStart() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if cfg.StartType == mgr.StartAutomatic {
		return nil
	}
	cfg.StartType = mgr.StartAutomatic
	return s.UpdateConfig(cfg)
}

// IsAdmin reports whether the current process has administrator privileges.
func IsAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}
