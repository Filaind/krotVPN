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

const (
	// redialMin / redialMax bound the backoff between attempts to (re)open a
	// channel; a channel that was up and died is redialed after redialMin.
	redialMin = 500 * time.Millisecond
	redialMax = 15 * time.Second
	// emptyGrace is how long a client tunnel may have no channel at all before
	// it gives up (Run returns and systemd restarts the client from scratch).
	emptyGrace = 45 * time.Second
)

// Dial opens a bonded tunnel. Every channel is dialed in parallel and Dial
// returns as soon as the first one is up (that response carries the address
// assignment); the rest attach as they connect. Each channel then has its own
// maintainer that redials it whenever it dies — with a fresh TCP connection,
// since on lossy paths a stalled flow rarely recovers while a new one usually
// works. All channels share one session id, so the server groups them (and
// rejoining channels) into a single logical link with one address.
//
// Dial fails only if the first attempt of every channel fails. The returned
// tunnel stays usable while channels come and go; it dies when it has had no
// channel for emptyGrace, or when the server answers a redial with a different
// address (the session expired on the server and a new one was created).
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

	tun := newTunnel(nil)
	tun.persistent = true
	tun.label = "krot"

	first := make(chan dialResult, n) // each maintainer reports its first attempt
	for slot := 0; slot < n; slot++ {
		go tun.maintain(cfg, sid[:], slot, n, first)
	}
	var assign *Assignment
	var firstErr error
	for i := 0; i < n && assign == nil; i++ {
		r := <-first
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		assign = r.assign
	}
	if assign == nil {
		tun.Close()
		return nil, nil, fmt.Errorf("no channel came up: %w", firstErr)
	}
	go tun.watchEmpty(emptyGrace)

	log.Printf("bonded tunnel up: %d/%d channels (rest connecting in background)", tun.channelCount(), n)
	return tun, assign, nil
}

type dialResult struct {
	assign *Assignment
	err    error
}

// wireIndex is the channel index sent to the server for a slot's gen-th
// connection. It rotates through slot, slot+n, slot+2n, … (< the session cap)
// so a redial does not reuse the index of a predecessor an older server may
// still hold, while staying ≡ slot mod n — slots never collide.
func wireIndex(slot, n, gen int) int {
	return slot + n*(gen%(maxChannelsPerSession/n))
}

// maintain keeps one channel slot connected for the tunnel's lifetime.
func (t *Tunnel) maintain(cfg ClientConfig, sid []byte, slot, n int, first chan<- dialResult) {
	backoff := redialMin
	reported := false
	for gen := 0; !t.isClosed(); gen++ {
		c, a, err := dialChannel(cfg, sid, wireIndex(slot, n, gen))
		if !reported {
			first <- dialResult{a, err}
			reported = true
		}
		if err != nil {
			log.Printf("krot: channel %d dial failed: %v (retry in %s)", slot, err, backoff)
			if !t.sleep(backoff) {
				return
			}
			backoff = min(backoff*2, redialMax)
			continue
		}
		if !t.claimAddr(a.Addr) {
			log.Printf("krot: server assigned %s on rejoin, session had %s: session expired, restarting", a.Addr, t.addr)
			c.Close()
			t.Close()
			return
		}
		done := t.addChannel(slot, c)
		if gen > 0 {
			log.Printf("krot: channel %d up again (%d live)", slot, t.channelCount())
		}
		backoff = redialMin
		<-done
		if !t.sleep(redialMin) {
			return
		}
	}
}

// claimAddr records the session address on the first successful channel and
// reports whether a later channel's assignment still matches it.
func (t *Tunnel) claimAddr(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.addr == "" {
		t.addr = addr
		return true
	}
	return t.addr == addr
}

// watchEmpty closes the tunnel once it has had no channel for grace.
func (t *Tunnel) watchEmpty(grace time.Duration) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var since time.Time
	for {
		select {
		case <-t.dead:
			return
		case now := <-tick.C:
			if t.channelCount() > 0 {
				since = time.Time{}
				continue
			}
			if since.IsZero() {
				since = now
			} else if now.Sub(since) >= grace {
				log.Printf("krot: no channel for %s, giving up", grace)
				t.Close()
				return
			}
		}
	}
}

// dialChannel performs one channel's full handshake: TCP, uTLS (Chrome), the
// WebSocket upgrade carrying the per-channel ephemeral key + session id + auth,
// then derives this channel's own directional AEAD keys.
func dialChannel(cfg ClientConfig, sid []byte, chanIdx int) (*Conn, *Assignment, error) {
	raw, err := net.DialTimeout("tcp", cfg.ServerAddr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("tcp dial: %w", err)
	}
	setUserTimeout(raw, TCPUserTimeout)

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
	conn, err := newConn(ws, keys.TxKey, keys.RxKey, pad, true)
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
