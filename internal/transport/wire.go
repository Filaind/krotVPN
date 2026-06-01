// Package transport is the Krot camouflage layer: a genuine TLS 1.3 session
// (Chrome-fingerprinted via uTLS on the client) carrying a WebSocket whose
// upgrade smuggles the key exchange and authentication. After the single real
// TLS handshake the wire shows only opaque WebSocket binary frames — there is
// no second, nested handshake for a traffic analyzer to fingerprint.
package transport

// Names used to smuggle the handshake through the WebSocket upgrade. Everything
// here is inside TLS 1.3 and thus invisible to a passive observer; innocuous
// names also survive a CDN that can read headers.
const (
	cookieEph  = "ek" // client ephemeral X25519 public key (raw-url base64)
	cookieTS   = "ts" // unix seconds
	cookieAuth = "au" // HMAC(PSK, eph||ts||serverStatic||sid) (raw-url base64)
	cookieSID  = "si" // bonding session id (raw-url base64, 16 bytes)
	cookieChan = "ci" // channel index within the bonded session (decimal)

	hdrServerEph  = "X-Accel-Token" // server ephemeral X25519 public key
	hdrAssignAddr = "X-Accel-Addr"  // assigned tunnel CIDR, e.g. 10.8.0.5/24
	hdrAssignGw   = "X-Accel-Gw"    // tunnel gateway, e.g. 10.8.0.1
	hdrAssignDNS  = "X-Accel-Dns"   // suggested DNS server
)

// maxChannelsPerSession caps how many channels one bonded tunnel may open, so a
// client (or a misbehaving peer) cannot exhaust server resources.
const maxChannelsPerSession = 16

// chromeUA matches a recent stable Chrome, consistent with the uTLS Chrome
// ClientHello fingerprint.
const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Assignment is the tunnel configuration the server hands the client.
type Assignment struct {
	Addr string // CIDR, e.g. 10.8.0.5/24
	Gw   string // gateway, e.g. 10.8.0.1
	DNS  string // suggested DNS resolver
}
