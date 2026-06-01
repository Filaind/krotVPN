package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"

	"github.com/krot-vpn/krot/internal/crypto"
	"github.com/krot-vpn/krot/internal/frame"
)

// ClientConfig parameterises a Dial.
type ClientConfig struct {
	ServerAddr   string   // ip:port actually dialed (connect by IP; SNI is separate)
	SNI          string   // TLS server name shown on the wire
	Path         string   // secret WebSocket path
	PSK          []byte   // 32-byte pre-shared key
	ServerStatic [32]byte // server static X25519 public key
	Insecure     bool     // skip cert chain verification (self-signed servers)
	PinSHA256    string   // optional base64 SHA-256 of the server cert SPKI
	Channels     int      // number of bonded channels (1 = classic single connection)
	Pad          frame.PadPolicy
}

// Dial opens a bonded tunnel: it brings up the first channel (which carries the
// address assignment), then opens the remaining channels in parallel, all
// sharing one session id so the server groups them into a single logical link.
// The tunnel is usable as long as at least one channel comes up; extra channels
// that fail to connect are simply skipped (degraded bandwidth, not failure).
func Dial(cfg ClientConfig) (*Tunnel, *Assignment, error) {
	n := cfg.Channels
	if n < 1 {
		n = 1
	}
	if n > maxChannelsPerSession {
		n = maxChannelsPerSession
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, nil, err
	}

	// Channel 0 first — it returns the address assignment and confirms auth.
	c0, assign, err := dialChannel(cfg, sid[:], 0)
	if err != nil {
		return nil, nil, fmt.Errorf("channel 0: %w", err)
	}

	tun := newTunnel(nil)
	tun.addChannel(0, c0)

	// Remaining channels in parallel; failures are tolerated.
	if n > 1 {
		type res struct {
			idx  int
			conn *Conn
		}
		ch := make(chan res, n-1)
		for i := 1; i < n; i++ {
			go func(idx int) {
				c, _, err := dialChannel(cfg, sid[:], idx)
				if err != nil {
					log.Printf("bond channel %d failed: %v", idx, err)
					ch <- res{idx, nil}
					return
				}
				ch <- res{idx, c}
			}(i)
		}
		for i := 1; i < n; i++ {
			r := <-ch
			if r.conn != nil {
				tun.addChannel(r.idx, r.conn)
			}
		}
	}

	log.Printf("bonded tunnel up: %d/%d channels", tun.channelCount(), n)
	return tun, assign, nil
}

// dialChannel performs one channel's full handshake: TCP, uTLS (Chrome), the
// WebSocket upgrade carrying the per-channel ephemeral key + session id + auth,
// then derives this channel's own directional AEAD keys.
func dialChannel(cfg ClientConfig, sid []byte, chanIdx int) (*Conn, *Assignment, error) {
	raw, err := net.DialTimeout("tcp", cfg.ServerAddr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("tcp dial: %w", err)
	}

	uconf := &utls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: cfg.Insecure,
		NextProtos:         []string{"h2", "http/1.1"}, // Chrome's set; server picks http/1.1
		MinVersion:         utls.VersionTLS13,
	}
	uconn := utls.UClient(raw, uconf, utls.HelloChrome_Auto)
	_ = uconn.SetDeadline(time.Now().Add(12 * time.Second))
	if err := uconn.Handshake(); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("tls handshake: %w", err)
	}
	if cfg.PinSHA256 != "" {
		if err := verifyPin(uconn, cfg.PinSHA256); err != nil {
			uconn.Close()
			return nil, nil, err
		}
	}

	eph, err := crypto.GenerateKeypair()
	if err != nil {
		uconn.Close()
		return nil, nil, err
	}
	ts := time.Now().Unix()
	token := authToken(cfg.PSK, eph.Public, ts, cfg.ServerStatic, sid)

	hdr := http.Header{}
	hdr.Set("User-Agent", chromeUA)
	hdr.Set("Origin", "https://"+cfg.SNI)
	hdr.Set("Accept-Language", "en-US,en;q=0.9")
	hdr.Set("Cookie", fmt.Sprintf("%s=%s; %s=%d; %s=%s; %s=%s; %s=%d",
		cookieEph, b64(eph.Public[:]),
		cookieTS, ts,
		cookieAuth, b64(token),
		cookieSID, b64(sid),
		cookieChan, chanIdx,
	))

	// Scheme "ws" (NOT "wss"): we already hand gorilla an established uTLS
	// connection, so it must not wrap it in a second TLS layer.
	u := &url.URL{Scheme: "ws", Host: cfg.SNI, Path: cfg.Path}
	ws, resp, err := websocket.NewClient(uconn, u, hdr, 1<<16, 1<<16)
	if err != nil {
		uconn.Close()
		if resp != nil {
			return nil, nil, fmt.Errorf("ws upgrade rejected (status %d): %w", resp.StatusCode, err)
		}
		return nil, nil, fmt.Errorf("ws upgrade: %w", err)
	}
	_ = uconn.SetDeadline(time.Time{})

	srvEph, err := decodeKey(resp.Header.Get(hdrServerEph))
	if err != nil {
		ws.Close()
		return nil, nil, fmt.Errorf("server ephemeral key: %w", err)
	}

	shared, err := combineDH(eph.Private, srvEph, eph.Private, cfg.ServerStatic)
	if err != nil {
		ws.Close()
		return nil, nil, err
	}
	// Mix the session id and channel index into the salt so every channel — and
	// every direction — gets a distinct key, even though they share a session.
	keys := crypto.DeriveSessionKeys(shared, channelSalt(eph.Public, srvEph, sid, chanIdx), true)

	pad := cfg.Pad
	if pad.BurstRecords == 0 && pad.BurstMax == 0 {
		pad = frame.DefaultPad
	}
	conn, err := newConn(ws, keys.TxKey, keys.RxKey, pad)
	if err != nil {
		ws.Close()
		return nil, nil, err
	}

	assign := &Assignment{
		Addr: resp.Header.Get(hdrAssignAddr),
		Gw:   resp.Header.Get(hdrAssignGw),
		DNS:  resp.Header.Get(hdrAssignDNS),
	}
	return conn, assign, nil
}

func verifyPin(c *utls.UConn, pin string) error {
	st := c.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificate to pin")
	}
	sum := sha256.Sum256(st.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != pin {
		return fmt.Errorf("cert pin mismatch: got %s", got)
	}
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func decodeKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// parseChan parses the channel-index cookie.
func parseChan(s string) (int, error) { return strconv.Atoi(s) }
