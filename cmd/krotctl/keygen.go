package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/krot-vpn/krot/internal/crypto"
)

// secrets is one freshly generated credential set.
type secrets struct {
	PSK  string // base64 std
	Priv string // base64 std (server static private)
	Pub  string // base64 std (server static public)
	Path string // secret WebSocket path
}

func genSecrets() (secrets, error) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return secrets{}, err
	}
	pr := make([]byte, 6)
	crypto.Random(pr)
	return secrets{
		PSK:  base64.StdEncoding.EncodeToString(psk),
		Priv: base64.StdEncoding.EncodeToString(kp.Private[:]),
		Pub:  base64.StdEncoding.EncodeToString(kp.Public[:]),
		Path: "/api/v2/" + base64.RawURLEncoding.EncodeToString(pr),
	}, nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("o", "", "directory to write a client.json template into (optional)")
	_ = fs.Parse(args)

	s, err := genSecrets()
	if err != nil {
		return err
	}

	fmt.Print("# ============================================================\n")
	fmt.Print("#  Krot credentials — keep PSK and server_priv SECRET\n")
	fmt.Print("# ============================================================\n\n")
	fmt.Printf("PSK (shared)       : %s\n", s.PSK)
	fmt.Printf("Server private key : %s\n", s.Priv)
	fmt.Printf("Server public key  : %s\n", s.Pub)
	fmt.Printf("Secret path        : %s\n\n", s.Path)
	fmt.Printf("Bring the server up with:\n")
	fmt.Printf("  sudo krotctl server up -psk '%s' -priv '%s'\n\n", s.PSK, s.Priv)

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		tmpl := fmt.Sprintf(`{
  "server_ip": "YOUR.SERVER.IP",
  "server_port": 443,
  "sni": "en.wikipedia.org",
  "path": "%s",
  "psk": "%s",
  "server_pub": "%s",
  "insecure": true,
  "tun_name": "krot0",
  "mtu": 1320,
  "channels": 4
}
`, s.Path, s.PSK, s.Pub)
		p := filepath.Join(*outDir, "client.json")
		if err := os.WriteFile(p, []byte(tmpl), 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote client template: %s (fill in server_ip)\n", p)
	}
	return nil
}
