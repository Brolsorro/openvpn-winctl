//go:build windows

// Package firewall manages Windows Firewall rules and IP forwarding.
package firewall

import (
	"fmt"
	"os/exec"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

const tcpipParamsKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

// EnsureRule adds an inbound firewall rule for OpenVPN if not already present.
func EnsureRule(port int, proto string) error {
	name := ruleName(port, proto)

	if err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
		"name="+name, "verbose=no").Run(); err == nil {
		fmt.Printf("[firewall] Rule already exists: %s\n", name)
		return nil
	}

	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir=in",
		"action=allow",
		"protocol="+proto,
		"localport="+strconv.Itoa(port),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("add firewall rule: %w\n%s", err, out)
	}
	fmt.Printf("[firewall] Rule added: %s (port %d/%s inbound allow)\n", name, port, proto)
	return nil
}

// DeleteRule removes the OpenVPN firewall rule.
func DeleteRule(port int, proto string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ruleName(port, proto), "protocol="+proto,
		"localport="+strconv.Itoa(port)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete firewall rule: %w\n%s", err, out)
	}
	fmt.Printf("[firewall] Rule deleted: %s\n", ruleName(port, proto))
	return nil
}

// EnableIPForwarding sets IPEnableRouter=1 in the registry.
func EnableIPForwarding() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParamsKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if val, _, err := k.GetIntegerValue("IPEnableRouter"); err == nil && val == 1 {
		fmt.Println("[routing] IP forwarding already enabled.")
		return nil
	}
	if err := k.SetDWordValue("IPEnableRouter", 1); err != nil {
		return fmt.Errorf("set IPEnableRouter: %w", err)
	}
	// Attempt to activate immediately — ignore error if service is already running.
	_ = exec.Command("net", "start", "RemoteAccess").Run()
	fmt.Println("[routing] IP forwarding enabled. A reboot may be required.")
	return nil
}

// DisableIPForwarding sets IPEnableRouter=0.
func DisableIPForwarding() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParamsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()
	if err := k.SetDWordValue("IPEnableRouter", 0); err != nil {
		return fmt.Errorf("set IPEnableRouter: %w", err)
	}
	fmt.Println("[routing] IP forwarding disabled.")
	return nil
}

// IPForwardingEnabled reports whether IPEnableRouter == 1.
func IPForwardingEnabled() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParamsKey, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	val, _, err := k.GetIntegerValue("IPEnableRouter")
	if err != nil {
		return false, nil
	}
	return val == 1, nil
}

func ruleName(port int, proto string) string {
	return fmt.Sprintf("OpenVPN %s %d", proto, port)
}
