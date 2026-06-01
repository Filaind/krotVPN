package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/crypto"
)

// derivePub returns the base64 X25519 public key for a 32-byte private key.
func derivePub(priv [32]byte) (string, error) {
	pub, err := crypto.PublicFromPrivate(priv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// writeServerConfig marshals cfg to serverCfgPath with 0600 perms (it holds the
// private key + PSK), creating /etc/krot if needed.
func writeServerConfig(cfg *config.Server) error {
	if err := os.MkdirAll(filepath.Dir(serverCfgPath), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(serverCfgPath, b, 0o600)
}

// writeClientConfig marshals a client config to path with 0600 perms (holds the
// PSK), creating /etc/krot if needed.
func writeClientConfig(path string, cfg *config.Client) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// installClientUnitTemplate writes a systemd TEMPLATE unit so each instance
// runs as krot-client@<name>, reading /etc/krot/client-<name>.json. The
// unit calls back into this binary (`client run`).
func installClientUnitTemplate() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=Krot VPN client (instance %%i)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s client run -config /etc/krot/client-%%i.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, self)
	return os.WriteFile(clientUnitTemplatePath, []byte(unit), 0o644)
}

// installServerUnit writes the systemd unit that runs `krotctl server run`.
// The unit calls back into this same binary, so one binary does everything.
func installServerUnit() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=Krot VPN server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s server run -config %s
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, self, serverCfgPath)
	return os.WriteFile(serverUnitPath, []byte(unit), 0o644)
}

// sh runs a command, returning a wrapped error with combined output on failure.
func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// svcActive returns "active"/"inactive"/... for a systemd unit.
func svcActive(unit string) string {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}

// printCmd runs a command and prints its first output line under a label.
func printCmd(label, name string, args ...string) {
	out, err := exec.Command(name, args...).Output()
	line := "n/a"
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			line = strings.SplitN(s, "\n", 2)[0]
		}
	}
	fmt.Printf("%s: %s\n", label, line)
}
