package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/client"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/config"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/easyrsa"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/firewall"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/install"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/pki"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/server"
	"github.com/YOUR_GITHUB_USERNAME/ovpn-manager/internal/system"
)

const usage = `OpenVPN Manager for Windows  v` + install.Version + `
https://github.com/YOUR_GITHUB_USERNAME/ovpn-manager

Usage:
  openvpn-manager [--config <path>] <command> [flags]

Global flags:
  --config <path>   Path to config.yaml (default: config.yaml next to exe)

Commands:
  install                       Download and install OpenVPN MSI
  uninstall [--remove-msi]      Remove PKI/configs (and optionally OpenVPN MSI)
  version                       Show installed component versions

  setup [--ca-password] [--pki-only]
  config generate               Regenerate server.ovpn (overwrites existing)
  config update                 Safe update: backup existing, write new from config.yaml

  client add    --name <n> [--password] [--ca-password]
  client revoke --name <n> [--ca-password]
  client renew  --name <n> [--ca-password]
  client show   --name <n>
  client list   [--verbose]
  client clean  --name <n>

  pki init        [--ca-password]   WARNING: destroys existing PKI
  pki backup
  pki sync                          Copy PKI files to config dir (safe)
  pki sync-crl    [--ca-password]   Regenerate and copy CRL (safe)
  pki show-expire [--days <n>]      Certs expiring within N days (default 90)
  pki show-revoked

  server connections            Show active VPN connections

  service start|stop|restart|status
  firewall enable|disable       [--port <n>] [--proto <udp|tcp>]
  firewall status
  routing enable|disable|status
`

func main() {
	if !system.IsAdmin() {
		fmt.Fprintln(os.Stderr, "ERROR: must be run as Administrator")
		os.Exit(1)
	}

	globalFS := flag.NewFlagSet("global", flag.ContinueOnError)
	cfgPath  := globalFS.String("config", "", "path to config.yaml")
	globalFS.Usage = func() { fmt.Print(usage) }

	if err := globalFS.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := globalFS.Args()
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		die("config: %v", err)
	}

	ctx := context.Background()
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "install":
		must(install.Install(cfg))
	case "uninstall":
		runUninstall(cfg, rest)
	case "version":
		install.Print(cfg)
	case "setup":
		runSetup(ctx, cfg, rest)
	case "config":
		runConfig(cfg, rest)
	case "client":
		runClient(ctx, cfg, rest)
	case "pki":
		runPKI(ctx, cfg, rest)
	case "server":
		runServer(cfg, rest)
	case "service":
		runService(rest)
	case "firewall":
		runFirewall(cfg, rest)
	case "routing":
		runRouting(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Print(usage)
		os.Exit(1)
	}
}

// ──────────────────────────────────────────────────────────────
// install / uninstall

func runUninstall(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	removeMSI := fs.Bool("remove-msi", false, "also uninstall OpenVPN MSI")
	fs.Parse(args)

	fmt.Print("This will delete ALL PKI data, configs and client files. Continue? [y/N]: ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "y" && confirm != "Y" {
		fmt.Println("Aborted.")
		return
	}
	must(install.Uninstall(cfg, *removeMSI))
}

// ──────────────────────────────────────────────────────────────
// setup / config

func runSetup(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	pkiOnly    := fs.Bool("pki-only", false, "only initialize PKI")
	caPassword := fs.Bool("ca-password", false, "protect CA key with a passphrase")
	fs.Parse(args)

	rs := easyrsa.New(cfg)
	pm := pki.New(cfg, rs)

	fmt.Println("=== PKI ===")
	must(pm.Init(ctx, *caPassword))

	if *pkiOnly {
		fmt.Println("PKI-only setup done.")
		return
	}

	fmt.Println("\n=== Server config ===")
	must(server.WriteConfig(cfg))

	fmt.Println("\n=== Firewall ===")
	must(firewall.EnsureRule(cfg.Server.Port, strings.TrimSuffix(cfg.Server.Proto, "4")))

	fmt.Println("\n=== IP forwarding ===")
	must(firewall.EnableIPForwarding())

	fmt.Println("\n=== Service ===")
	must(system.Start())

	fmt.Println("\n[OK] Setup complete.")
	fmt.Printf("  Server config : %s\\server.ovpn\n", cfg.ConfigAuto)
	fmt.Printf("  Keys          : %s\n", cfg.ConfigDir)
	fmt.Printf("  Logs          : %s\n", cfg.LogsDir)
	fmt.Println("  NOTE: reboot may be required for IP forwarding.")
}

func runConfig(cfg *config.Config, args []string) {
	if len(args) == 0 {
		die("usage: config <generate|update>")
	}
	switch args[0] {
	case "generate":
		// Write fresh config, overwrite existing
		must(server.WriteConfig(cfg))
	case "update":
		// Safe update: backup existing, write new from config.yaml
		// Previous config is preserved in pki-backups/server_<timestamp>.ovpn
		must(server.UpdateConfig(cfg))
		fmt.Println("Run: openvpn-manager service restart")
	default:
		die("unknown config subcommand: %s", args[0])
	}
}

// ──────────────────────────────────────────────────────────────
// client

func runClient(ctx context.Context, cfg *config.Config, args []string) {
	if len(args) == 0 {
		die("usage: client <add|revoke|renew|show|list|clean> [flags]")
	}

	rs := easyrsa.New(cfg)
	cm := client.New(cfg, rs)
	sub, rest := args[0], args[1:]

	switch sub {
	case "add":
		fs := flag.NewFlagSet("client add", flag.ExitOnError)
		name       := fs.String("name", "", "client name (required)")
		password   := fs.Bool("password", false, "protect client key with passphrase")
		caPassword := fs.Bool("ca-password", false, "CA key is password-protected")
		fs.Parse(rest)
		requireFlag(*name, "--name")
		if *caPassword {
			must(rs.AskCAPassword())
		}
		must(cm.Add(ctx, *name, *password))

	case "revoke":
		fs := flag.NewFlagSet("client revoke", flag.ExitOnError)
		name       := fs.String("name", "", "client name (required)")
		caPassword := fs.Bool("ca-password", false, "CA key is password-protected")
		fs.Parse(rest)
		requireFlag(*name, "--name")
		if *caPassword {
			must(rs.AskCAPassword())
		}
		must(cm.Revoke(ctx, *name))
		fmt.Println("Run: openvpn-manager service restart")

	case "renew":
		fs := flag.NewFlagSet("client renew", flag.ExitOnError)
		name       := fs.String("name", "", "client name (required)")
		caPassword := fs.Bool("ca-password", false, "CA key is password-protected")
		fs.Parse(rest)
		requireFlag(*name, "--name")
		if *caPassword {
			must(rs.AskCAPassword())
		}
		must(cm.Renew(ctx, *name))

	case "show":
		fs := flag.NewFlagSet("client show", flag.ExitOnError)
		name := fs.String("name", "", "client name (required)")
		fs.Parse(rest)
		requireFlag(*name, "--name")
		must(server.ShowCertInfo(cfg, *name))

	case "list":
		fs := flag.NewFlagSet("client list", flag.ExitOnError)
		verbose := fs.Bool("verbose", false, "include expiry info")
		fs.Parse(rest)
		if *verbose {
			must(cm.ListVerbose())
		} else {
			must(cm.List())
		}

	case "clean":
		fs := flag.NewFlagSet("client clean", flag.ExitOnError)
		name := fs.String("name", "", "client name (required)")
		fs.Parse(rest)
		requireFlag(*name, "--name")
		must(cm.Clean(*name))

	default:
		die("unknown client subcommand: %s", sub)
	}
}

// ──────────────────────────────────────────────────────────────
// pki

func runPKI(ctx context.Context, cfg *config.Config, args []string) {
	if len(args) == 0 {
		die("usage: pki <init|backup|sync|sync-crl|show-expire|show-revoked>")
	}

	rs := easyrsa.New(cfg)
	pm := pki.New(cfg, rs)
	sub, rest := args[0], args[1:]

	switch sub {
	case "init":
		fs := flag.NewFlagSet("pki init", flag.ExitOnError)
		caPassword := fs.Bool("ca-password", false, "protect CA key with a passphrase")
		fs.Parse(rest)
		must(pm.Init(ctx, *caPassword))

	case "backup":
		must(rs.BackupPKI())

	case "sync":
		must(pm.SyncConfigDir())

	case "sync-crl":
		fs := flag.NewFlagSet("pki sync-crl", flag.ExitOnError)
		caPassword := fs.Bool("ca-password", false, "CA key is password-protected")
		fs.Parse(rest)
		if *caPassword {
			must(rs.AskCAPassword())
		}
		must(pm.SyncCRL(ctx))
		fmt.Println("Run: openvpn-manager service restart")

	case "show-expire":
		fs := flag.NewFlagSet("pki show-expire", flag.ExitOnError)
		days := fs.Int("days", 90, "warn threshold in days")
		fs.Parse(rest)
		must(server.ShowExpiring(cfg, *days))

	case "show-revoked":
		must(server.ShowRevoked(cfg))

	default:
		die("unknown pki subcommand: %s", sub)
	}
}

// ──────────────────────────────────────────────────────────────
// server

func runServer(cfg *config.Config, args []string) {
	if len(args) == 0 || args[0] != "connections" {
		die("usage: server connections")
	}
	must(server.ShowConnections(cfg))
}

// ──────────────────────────────────────────────────────────────
// service

func runService(args []string) {
	if len(args) == 0 {
		die("usage: service <start|stop|restart|status>")
	}
	switch args[0] {
	case "start":
		must(system.Start())
	case "stop":
		must(system.Stop())
	case "restart":
		must(system.Restart())
	case "status":
		st, err := system.Status()
		must(err)
		fmt.Printf("%s: %s\n", system.ServiceName, st)
	default:
		die("unknown service subcommand: %s", args[0])
	}
}

// ──────────────────────────────────────────────────────────────
// firewall / routing

func runFirewall(cfg *config.Config, args []string) {
	if len(args) == 0 {
		die("usage: firewall <enable|disable|status>")
	}
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	port  := fs.Int("port", cfg.Server.Port, "port")
	proto := fs.String("proto", cfg.Server.Proto, "protocol (udp, tcp)")
	fs.Parse(args[1:])
	p := strings.TrimSuffix(*proto, "4")

	switch args[0] {
	case "enable":
		must(firewall.EnsureRule(*port, p))
	case "disable":
		must(firewall.DeleteRule(*port, p))
	case "status":
		on, err := firewall.IPForwardingEnabled()
		must(err)
		fmt.Printf("IP forwarding: %v\n", on)
	default:
		die("unknown firewall subcommand: %s", args[0])
	}
}

func runRouting(args []string) {
	if len(args) == 0 {
		die("usage: routing <enable|disable|status>")
	}
	switch args[0] {
	case "enable":
		must(firewall.EnableIPForwarding())
	case "disable":
		must(firewall.DisableIPForwarding())
	case "status":
		on, err := firewall.IPForwardingEnabled()
		must(err)
		if on {
			fmt.Println("IP forwarding: enabled")
		} else {
			fmt.Println("IP forwarding: disabled")
		}
	default:
		die("unknown routing subcommand: %s", args[0])
	}
}

// ──────────────────────────────────────────────────────────────
// helpers

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}

func requireFlag(val, name string) {
	if val == "" {
		die("%s is required", name)
	}
}
