// Package config defines the on-disk JSON configuration for the Krot server
// and client plus helpers to load and validate it.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/krot-vpn/krot/internal/crypto"
)

// Server is the server daemon configuration.
type Server struct {
	Listen     string `json:"listen"`      // bind address, e.g. ":443"
	SNI        string `json:"sni"`         // TLS server name (used for the self-signed cert)
	Path       string `json:"path"`        // secret WebSocket path
	PSK        string `json:"psk"`         // base64 of the 32-byte pre-shared key
	ServerPriv string `json:"server_priv"` // base64 of the 32-byte X25519 static private key
	CertFile   string `json:"cert_file"`   // PEM cert chain (e.g. Let's Encrypt fullchain)
	KeyFile    string `json:"key_file"`    // PEM private key
	SelfSigned bool   `json:"self_signed"` // generate a throwaway cert (testing only)
	Decoy      string `json:"decoy"`       // URL probes / unauth traffic are proxied to
	TunName    string `json:"tun_name"`    // e.g. "krot0"
	TunCIDR    string `json:"tun_cidr"`    // gateway addr+mask, e.g. "10.8.0.1/24"
	DNS        string `json:"dns"`         // DNS handed to clients, e.g. "1.1.1.1"
	WANIface   string `json:"wan_iface"`   // egress iface for NAT ("" = auto-detect)
	MTU        int    `json:"mtu"`         // tunnel MTU
}

// Client is the client daemon configuration.
type Client struct {
	ServerIP    string `json:"server_ip"`    // IP actually dialed
	ServerPort  int    `json:"server_port"`  // usually 443
	SNI         string `json:"sni"`          // TLS server name sent on the wire
	Path        string `json:"path"`         // secret WebSocket path
	PSK         string `json:"psk"`          // base64 of the 32-byte pre-shared key
	ServerPub   string `json:"server_pub"`   // base64 of the server's 32-byte X25519 public key
	Insecure    bool   `json:"insecure"`     // skip cert verification (self-signed servers)
	PinSHA256   string `json:"pin_sha256"`   // optional base64 SHA-256 of server cert SPKI
	TunName     string `json:"tun_name"`     // e.g. "krot0"
	MTU         int    `json:"mtu"`          // tunnel MTU (must match server)
	DNS         string `json:"dns"`          // optional DNS override
	Channels    int    `json:"channels"`     // bonded parallel connections (1 = classic; default 4)
	RouteMode   string `json:"route_mode"`   // "full" (default): grab default route+DNS. "manual": only bring up TUN, leave routing to the operator (for policy-routing / xray chaining).
	SocksListen string `json:"socks_listen"` // if set (e.g. "127.0.0.1:1080"), expose a SOCKS5 proxy that egresses via the tunnel. Implies route_mode=manual. Point xray's outbound here for clean chaining.
	SocksTable  string `json:"socks_table"`  // policy-routing table id for SOCKS source routing (default "100"). Use a distinct value when running multiple krot clients on one host.
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	var c Server
	if err := loadJSON(path, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	if _, err := DecodeKey32(c.ServerPriv); err != nil {
		return nil, fmt.Errorf("server_priv: %w", err)
	}
	if !c.SelfSigned && (c.CertFile == "" || c.KeyFile == "") {
		return nil, fmt.Errorf("cert_file/key_file required unless self_signed is true")
	}
	return &c, nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := loadJSON(path, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	if _, err := DecodeKey32(c.ServerPub); err != nil {
		return nil, fmt.Errorf("server_pub: %w", err)
	}
	if c.ServerIP == "" {
		return nil, fmt.Errorf("server_ip is required")
	}
	if c.SNI == "" {
		return nil, fmt.Errorf("sni is required")
	}
	return &c, nil
}

func (c *Server) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.Path == "" {
		c.Path = "/api/v2/stream"
	}
	if c.TunName == "" {
		c.TunName = "krot0"
	}
	if c.TunCIDR == "" {
		c.TunCIDR = "10.8.0.1/24"
	}
	if c.MTU == 0 {
		c.MTU = 1320
	}
}

func (c *Client) applyDefaults() {
	if c.ServerPort == 0 {
		c.ServerPort = 443
	}
	if c.Path == "" {
		c.Path = "/api/v2/stream"
	}
	if c.TunName == "" {
		c.TunName = "krot0"
	}
	if c.MTU == 0 {
		c.MTU = 1320
	}
	if c.Channels == 0 {
		c.Channels = 4 // bonding default: per-flow throttling makes this ~Nx faster
	}
}

// DecodePSK decodes and length-checks the base64 pre-shared key.
func DecodePSK(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("psk is not valid base64: %w", err)
	}
	if len(b) != crypto.KeySize {
		return nil, fmt.Errorf("psk must decode to %d bytes, got %d", crypto.KeySize, len(b))
	}
	return b, nil
}

// DecodeKey32 decodes a base64 32-byte key.
func DecodeKey32(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("not valid base64: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("must decode to 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

func loadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}
