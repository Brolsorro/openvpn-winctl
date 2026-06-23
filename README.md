# ovpn-manager

> **⚠️ WORK IN PROGRESS — не использовать в production**
>
> Это тестовая версия в активной разработке. API, конфигурация и поведение могут меняться без предупреждения. Обратная совместимость не гарантируется.

![Status](https://img.shields.io/badge/status-development-orange)
![Stability](https://img.shields.io/badge/stability-experimental-red)

CLI tool for managing OpenVPN 2.6.x + EasyRSA 3.x on Windows.

Single self-contained `.exe` — no dependencies, no runtime required.

## Requirements

- Windows 10/11 or Server 2019+
- [OpenVPN 2.6.x](https://openvpn.net/community-downloads/) with EasyRSA component
- Run as Administrator

## Build

```powershell
# On Windows
go mod tidy
go build -ldflags="-s -w" -o openvpn-manager.exe ./cmd/ovpn-manager

# Cross-compile from Linux/macOS
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o openvpn-manager.exe ./cmd/ovpn-manager
```

## Setup

1. Copy `openvpn-manager.exe` and `config.yaml.example` to the same directory
2. Create your config from the example:
   ```powershell
   copy config.yaml.example config.yaml
   ```
3. Edit `config.yaml` — at minimum set `server.public_ip`
4. Run from an Administrator terminal

> `config.yaml` is in `.gitignore` — your server IP and settings
> stay out of version control. Commit only `config.yaml.example`.

```powershell
.\openvpn-manager.exe setup
```

Or use the provided `ovpn.bat` wrapper from the OpenVPN install directory.

## Usage

```
# First-time setup (PKI + server config + firewall + service)
openvpn-manager setup
openvpn-manager setup --ca-password        # protect CA key with passphrase

# Clients
openvpn-manager client add    --name laptop
openvpn-manager client add    --name phone  --password         # encrypted key
openvpn-manager client add    --name server --ca-password      # CA has password
openvpn-manager client revoke --name laptop --ca-password
openvpn-manager client renew  --name laptop --ca-password
openvpn-manager client show   --name laptop
openvpn-manager client list
openvpn-manager client list   --verbose     # with expiry dates
openvpn-manager client clean  --name laptop # remove stale files

# PKI maintenance
openvpn-manager pki backup
openvpn-manager pki sync                    # copy PKI → config (safe)
openvpn-manager pki sync-crl               # refresh CRL (safe)
openvpn-manager pki sync-crl --ca-password
openvpn-manager pki show-expire            # expiring within 90 days
openvpn-manager pki show-expire --days 30
openvpn-manager pki show-revoked

# Server monitoring
openvpn-manager server connections

# Service
openvpn-manager service status
openvpn-manager service restart

# Firewall & routing
openvpn-manager firewall enable  --port 1194 --proto udp
openvpn-manager routing enable

# System info
openvpn-manager version
openvpn-manager install    # download and install OpenVPN MSI
```

## How EasyRSA is invoked

OpenVPN 2.6.x ships EasyRSA as a bash script (`easy-rsa/easyrsa`).
The bundled `easy-rsa/bin/sh.exe` (mksh/Win32) executes it.
All Unix utilities (`grep`, `printf`, `awk`, `sed`) live in `easy-rsa/bin/`.

This tool invokes:
```
sh.exe -c "./easyrsa --batch <command>"
```
with `WorkingDirectory = easy-rsa/` and
`PATH = easy-rsa/;easy-rsa/bin/;OpenVPN/bin/;...`

`os/exec` passes `WorkingDirectory` at OS level via `CreateProcess` —
no shell quoting, no spaces-in-path issues.

## Password security

CA key passphrase and client key passphrases are:
- Read via `term.ReadPassword` (Windows `ReadConsole` with `ENABLE_ECHO_INPUT=false`)
- Stored as `[]byte` and zeroed from memory after use
- Passed to openssl via `EASYRSA_PASSIN=file:<tmpfile>` / `EASYRSA_PASSOUT=file:<tmpfile>`
- Temp files are zeroed and deleted immediately after the command completes

The passphrase never appears in process argument lists or shell history.

## Project structure

```
cmd/ovpn-manager/    CLI entry point (thin, only flag routing)
internal/
  config/            Config loading and path derivation
  easyrsa/           EasyRSA runner via bundled sh.exe
  pki/               PKI lifecycle (init, sync, backup)
  client/            Client cert management and .ovpn generation
  server/            Server config generation and monitoring
  install/           OpenVPN MSI install/uninstall and version info
  firewall/          Windows Firewall rules and IP forwarding
  system/            Windows service management
```

## License

MIT
