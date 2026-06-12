//go:build windows

// Package easyrsa wraps EasyRSA 3.x on Windows.
//
// # How EasyRSA works on Windows
//
// OpenVPN 2.6.x ships EasyRSA as a POSIX shell script (easy-rsa/easyrsa).
// The bundled easy-rsa/bin/sh.exe (mksh/Win32) executes it.
// All Unix utilities (grep, printf, awk, sed) live in easy-rsa/bin/.
//
// Correct invocation matches what EasyRSA-Start.bat does:
//
//	PATH = <easy-rsa>;<easy-rsa/bin>;<openvpn/bin>;$PATH
//	WorkingDirectory = <easy-rsa>
//	sh.exe -c "./easyrsa --batch <command>"
//
// os/exec passes WorkingDirectory at OS level via CreateProcess — paths
// with spaces in "Program Files" never reach the shell parser.
//
// # Password handling
//
// openssl reads the CA key passphrase directly from /dev/tty, bypassing stdin.
// The correct solution is EASYRSA_PASSIN=file:<path> — easyrsa passes it to
// openssl via -passin flag, never exposing it in the process argument list.
// The temp file is deleted immediately after the command completes.
package easyrsa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Brolsorro/ovpn-manager/internal/config"
)

// Commander is the interface for running easyrsa commands.
// Using an interface makes the PKI and client layers testable via mocks.
type Commander interface {
	Run(ctx context.Context, command string) error
	RunWithStdin(ctx context.Context, command, stdin string) error
}

// Runner executes easyrsa commands via the bundled sh.exe.
type Runner struct {
	cfg    *config.Config
	caPass []byte // zeroed after use; never stored as string
}

// New returns a new Runner. Call AskCAPassword before commands
// that access the CA private key if the CA was created with --ca-password.
func New(cfg *config.Config) *Runner {
	return &Runner{cfg: cfg}
}

// AskCAPassword reads the CA passphrase securely (hidden input).
// The passphrase is stored as []byte so it can be zeroed from memory.
func (r *Runner) AskCAPassword() error {
	fmt.Print("  CA key passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read CA passphrase: %w", err)
	}
	if len(pass) == 0 {
		return fmt.Errorf("CA passphrase cannot be empty")
	}
	r.caPass = pass
	return nil
}

// ClearCAPass zeros the passphrase bytes and releases the slice.
func (r *Runner) ClearCAPass() {
	for i := range r.caPass {
		r.caPass[i] = 0
	}
	r.caPass = nil
}

// HasCAPass reports whether a CA passphrase has been set.
func (r *Runner) HasCAPass() bool {
	return len(r.caPass) > 0
}

// Run executes an easyrsa --batch command with no stdin input.
func (r *Runner) Run(ctx context.Context, command string) error {
	return r.execute(ctx, command, nil)
}

// RunWithStdin executes an easyrsa command passing stdinText to the process.
// Used for commands that require confirmation (e.g. revoke expects "yes").
func (r *Runner) RunWithStdin(ctx context.Context, command, stdinText string) error {
	return r.execute(ctx, command, strings.NewReader(stdinText))
}

// BuildCA creates the CA. If withPassword is true, prompts for passphrase
// (hidden input) and stores it for subsequent commands in this session.
func (r *Runner) BuildCA(ctx context.Context, withPassword bool) error {
	if !withPassword {
		return r.execute(ctx, "build-ca nopass", nil)
	}

	pass, err := readPassphraseTwice("New CA passphrase")
	if err != nil {
		return err
	}
	defer zeroBytes(pass)

	r.caPass = make([]byte, len(pass))
	copy(r.caPass, pass)

	return r.executeWithPassout(ctx, "build-ca", pass)
}

// BuildClientFull creates a client keypair and signs it.
// If withPassword is true, prompts for the client key passphrase (hidden).
func (r *Runner) BuildClientFull(ctx context.Context, name string, withPassword bool) error {
	if !withPassword {
		return r.execute(ctx, "build-client-full "+name+" nopass", nil)
	}

	pass, err := readPassphraseTwice("New client key passphrase")
	if err != nil {
		return err
	}
	defer zeroBytes(pass)

	return r.executeWithPassout(ctx, "build-client-full "+name, pass)
}

// Renew renews an existing client certificate.
func (r *Runner) Renew(ctx context.Context, name string) error {
	return r.execute(ctx, "renew "+name, nil)
}

// ──────────────────────────────────────────────
// core executor

func (r *Runner) execute(ctx context.Context, command string, stdin io.Reader) error {
	if err := r.validate(); err != nil {
		return err
	}

	removeLockFile(r.cfg.PkiDir)

	env, cleanup, err := r.buildEnv(nil)
	if err != nil {
		return err
	}
	defer cleanup()

	return r.runProcess(ctx, command, stdin, env)
}

// executeWithPassout runs with EASYRSA_PASSOUT set to a temp file
// containing the given passphrase. The file is securely deleted after.
func (r *Runner) executeWithPassout(ctx context.Context, command string, passout []byte) error {
	if err := r.validate(); err != nil {
		return err
	}

	removeLockFile(r.cfg.PkiDir)

	env, cleanup, err := r.buildEnv(passout)
	if err != nil {
		return err
	}
	defer cleanup()

	return r.runProcess(ctx, command, nil, env)
}

// buildEnv constructs the process environment:
//   - PATH with easy-rsa dirs prepended
//   - EASYRSA_PASSIN written to a temp file (if CA pass is set)
//   - EASYRSA_PASSOUT written to a temp file (if passout provided)
//
// Returns cleanup func that zeros and removes temp files.
func (r *Runner) buildEnv(passout []byte) (env []string, cleanup func(), err error) {
	cleanup = func() {} // no-op default

	envPath := strings.Join([]string{
		r.cfg.EasyRsaDir,
		r.cfg.BinDir,
		filepath.Join(r.cfg.OpenVPNRoot, "bin"),
		os.Getenv("PATH"),
	}, ";")

	env = os.Environ()
	for i, e := range env {
		if strings.EqualFold(e[:min(len(e), 5)], "PATH=") {
			env[i] = "PATH=" + envPath
			break
		}
	}

	var tempFiles []string
	cleanup = func() {
		for _, f := range tempFiles {
			// Zero the file contents before removing
			if info, err := os.Stat(f); err == nil {
				zeros := make([]byte, info.Size())
				_ = os.WriteFile(f, zeros, 0600)
			}
			_ = os.Remove(f)
		}
	}

	// CA passphrase → EASYRSA_PASSIN=file:<tmp>
	if len(r.caPass) > 0 {
		f, ferr := writeTempPass(r.caPass)
		if ferr != nil {
			return nil, cleanup, fmt.Errorf("write CA passin file: %w", ferr)
		}
		tempFiles = append(tempFiles, f)
		env = append(env, "EASYRSA_PASSIN=file:"+f)
	}

	// New key passphrase → EASYRSA_PASSOUT=file:<tmp>
	if len(passout) > 0 {
		f, ferr := writeTempPass(passout)
		if ferr != nil {
			return nil, cleanup, fmt.Errorf("write passout file: %w", ferr)
		}
		tempFiles = append(tempFiles, f)
		env = append(env, "EASYRSA_PASSOUT=file:"+f)
	}

	return env, cleanup, nil
}

func (r *Runner) runProcess(ctx context.Context, command string, stdin io.Reader, env []string) error {
	args := []string{"-c", "./easyrsa --batch " + command}
	cmd := exec.CommandContext(ctx, r.cfg.ShExe, args...)
	cmd.Dir = r.cfg.EasyRsaDir
	cmd.Env = env

	if stdin != nil {
		cmd.Stdin = stdin
	}

	var errBuf bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &errBuf)

	fmt.Printf("  → easyrsa %s\n", command)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("easyrsa %q: %w", command, err)
	}
	return nil
}

func (r *Runner) validate() error {
	if _, err := os.Stat(r.cfg.ShExe); err != nil {
		return fmt.Errorf("sh.exe not found at %s: install OpenVPN with EasyRSA component", r.cfg.ShExe)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.EasyRsaDir, "easyrsa")); err != nil {
		return fmt.Errorf("easyrsa script not found in %s", r.cfg.EasyRsaDir)
	}
	return nil
}

// ──────────────────────────────────────────────
// BackupPKI

// BackupPKI copies the pki directory to pki-backups/<timestamp>.
func (r *Runner) BackupPKI() error {
	if !r.cfg.Backup.Enabled {
		return nil
	}
	if _, err := os.Stat(r.cfg.PkiDir); err != nil {
		return nil // nothing to back up yet
	}
	if err := os.MkdirAll(r.cfg.BackupDir, 0o755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	ts := time.Now().Format("20060102_150405")
	dest := filepath.Join(r.cfg.BackupDir, "pki_"+ts)
	fmt.Printf("  Backing up PKI to %s ...\n", dest)
	if err := copyDir(r.cfg.PkiDir, dest); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	fmt.Println("  Backup done.")
	return nil
}

// ──────────────────────────────────────────────
// helpers

func removeLockFile(pkiDir string) {
	lock := filepath.Join(pkiDir, "lock.file")
	if _, err := os.Stat(lock); err == nil {
		fmt.Println("  Removing stale lock file...")
		_ = os.Remove(lock)
	}
}

// writeTempPass writes passphrase bytes to a 0600 temp file and returns its path.
func writeTempPass(pass []byte) (string, error) {
	f, err := os.CreateTemp("", "ovpn-pass-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(pass); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// readPassphraseTwice prompts for a passphrase twice and confirms they match.
func readPassphraseTwice(prompt string) ([]byte, error) {
	fmt.Printf("  %s: ", prompt)
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	fmt.Printf("  Confirm %s: ", strings.ToLower(prompt))
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read passphrase confirmation: %w", err)
	}
	defer zeroBytes(p2)

	if !bytes.Equal(p1, p2) {
		zeroBytes(p1)
		return nil, fmt.Errorf("passphrases do not match")
	}
	if len(p1) < 4 {
		zeroBytes(p1)
		return nil, fmt.Errorf("passphrase must be at least 4 characters")
	}
	return p1, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
