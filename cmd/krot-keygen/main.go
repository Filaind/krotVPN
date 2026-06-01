// Command krot-keygen generates the shared secrets for a Krot deployment:
// a pre-shared key, the server's static X25519 identity, and a random secret
// path. It prints ready-to-edit server and client config snippets.
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/krot-vpn/krot/internal/crypto"
)

func main() {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)

	kp, err := crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("keygen error:", err)
		return
	}

	pathRand := make([]byte, 6)
	crypto.Random(pathRand)
	path := "/api/v2/" + base64.RawURLEncoding.EncodeToString(pathRand)

	pskB64 := base64.StdEncoding.EncodeToString(psk)
	privB64 := base64.StdEncoding.EncodeToString(kp.Private[:])
	pubB64 := base64.StdEncoding.EncodeToString(kp.Public[:])

	fmt.Print(`# ============================================================
#  Krot credentials — keep psk and server_priv SECRET
# ============================================================

`)
	fmt.Printf("PSK (shared)         : %s\n", pskB64)
	fmt.Printf("Server private key   : %s\n", privB64)
	fmt.Printf("Server public key    : %s\n", pubB64)
	fmt.Printf("Secret path          : %s\n\n", path)

	fmt.Printf(`---- server.json (put on the server) ----
{
  "listen": ":443",
  "sni": "your-domain.example",
  "path": "%s",
  "psk": "%s",
  "server_priv": "%s",
  "cert_file": "/etc/letsencrypt/live/your-domain.example/fullchain.pem",
  "key_file": "/etc/letsencrypt/live/your-domain.example/privkey.pem",
  "self_signed": false,
  "decoy": "https://www.wikipedia.org",
  "tun_name": "krot0",
  "tun_cidr": "10.8.0.1/24",
  "dns": "1.1.1.1",
  "wan_iface": "",
  "mtu": 1380
}

---- client.json (put on the client) ----
{
  "server_ip": "YOUR.SERVER.IP.ADDR",
  "server_port": 443,
  "sni": "your-domain.example",
  "path": "%s",
  "psk": "%s",
  "server_pub": "%s",
  "insecure": false,
  "tun_name": "krot0",
  "mtu": 1380
}
`, path, pskB64, privB64, path, pskB64, pubB64)
}
