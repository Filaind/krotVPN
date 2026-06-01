package transport

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/krot-vpn/krot/internal/crypto"
	"github.com/krot-vpn/krot/internal/frame"
)

// authWindow is the accepted clock skew (seconds) on the auth timestamp.
const authWindow = 120

// HandlerConfig configures the server-side HTTP handler.
type HandlerConfig struct {
	PSK    []byte
	Static crypto.Keypair // server static identity
	Path   string         // secret WebSocket path
	Gw     string         // tunnel gateway handed to clients
	DNS    string         // suggested DNS handed to clients
	Decoy  string         // URL to reverse-proxy unauthenticated requests to
	Pad    frame.PadPolicy
	Replay *crypto.ReplayFilter

	// Alloc reserves a tunnel address; ok=false means the pool is exhausted,
	// in which case the request is served the decoy so a probe learns nothing.
	Alloc func() (cidr string, release func(), ok bool)
	// OnConn runs once for the lifetime of an authenticated bonded tunnel, in
	// its own goroutine. It returns when the tunnel loses its last channel.
	OnConn func(tun *Tunnel, assign Assignment)
}

// serverSession is one bonded tunnel on the server, keyed by the client's
// session id. Channels with the same sid attach to the same *Tunnel.
type serverSession struct {
	tun    *Tunnel
	assign Assignment
}

// Handler authenticates and upgrades Krot clients and reverse-proxies
// everything else to the decoy, so the endpoint looks like an ordinary website
// to active probes.
type Handler struct {
	cfg      HandlerConfig
	upgrader websocket.Upgrader
	decoy    http.Handler

	mu       sync.Mutex
	sessions map[string]*serverSession // sid -> bonded tunnel
}

// NewHandler builds the server HTTP handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if len(cfg.PSK) != crypto.KeySize {
		return nil, fmt.Errorf("psk must be %d bytes", crypto.KeySize)
	}
	if cfg.Pad.BurstRecords == 0 && cfg.Pad.BurstMax == 0 {
		cfg.Pad = frame.DefaultPad
	}
	if cfg.Replay == nil {
		// Remember a token for the full span over which it could be accepted
		// (a timestamp is valid for ±authWindow, i.e. a 2×authWindow window).
		cfg.Replay = crypto.NewReplayFilter(2 * authWindow * time.Second)
	}
	h := &Handler{
		cfg: cfg,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1 << 16,
			WriteBufferSize: 1 << 16,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		sessions: make(map[string]*serverSession),
	}
	h.decoy = buildDecoy(cfg.Decoy)
	return h, nil
}

func buildDecoy(target string) http.Handler {
	if target == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Server", "nginx")
			_, _ = w.Write([]byte("<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"))
		})
	}
	u, err := url.Parse(target)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		})
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	rp.Director = func(req *http.Request) {
		orig(req)
		req.Host = u.Host // make the decoy answer for its own host
	}
	return rp
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientEph, sid, chanIdx, ok := h.checkAuth(r)
	if !ok || r.URL.Path != h.cfg.Path {
		h.decoy.ServeHTTP(w, r)
		return
	}
	sidKey := string(sid)

	// Look up an existing bonded session for this sid, or reserve an address
	// and create one. Only the FIRST channel of a session allocates an address;
	// later channels join the existing tunnel.
	h.mu.Lock()
	sess, joining := h.sessions[sidKey]
	if !joining {
		cidr, release, ok := h.cfg.Alloc()
		if !ok {
			h.mu.Unlock()
			h.decoy.ServeHTTP(w, r) // pool exhausted: reveal nothing
			return
		}
		assign := Assignment{Addr: cidr, Gw: h.cfg.Gw, DNS: h.cfg.DNS}
		// onEmpty fires once when the last channel leaves: free addr + unregister.
		tun := newTunnel(func() {
			h.mu.Lock()
			delete(h.sessions, sidKey)
			h.mu.Unlock()
			release()
		})
		sess = &serverSession{tun: tun, assign: assign}
		h.sessions[sidKey] = sess
		h.mu.Unlock()

		// Run OnConn for the tunnel's lifetime in the background; this handler
		// goroutine stays alive only as long as this channel's read loop.
		go h.cfg.OnConn(tun, assign)
	} else {
		// Enforce the per-session channel cap.
		if sess.tun.channelCount() >= maxChannelsPerSession {
			h.mu.Unlock()
			h.decoy.ServeHTTP(w, r)
			return
		}
		h.mu.Unlock()
	}

	eph, err := crypto.GenerateKeypair()
	if err != nil {
		h.decoy.ServeHTTP(w, r)
		return
	}

	respHdr := http.Header{}
	respHdr.Set(hdrServerEph, b64(eph.Public[:]))
	respHdr.Set(hdrAssignAddr, sess.assign.Addr)
	respHdr.Set(hdrAssignGw, sess.assign.Gw)
	if sess.assign.DNS != "" {
		respHdr.Set(hdrAssignDNS, sess.assign.DNS)
	}
	respHdr.Set("Server", "nginx")

	ws, err := h.upgrader.Upgrade(w, r, respHdr)
	if err != nil {
		return // Upgrade already wrote an error; tunnel cleans up via its own channels
	}

	shared, err := combineDH(eph.Private, clientEph, h.cfg.Static.Private, clientEph)
	if err != nil {
		ws.Close()
		return
	}
	keys := crypto.DeriveSessionKeys(shared, channelSalt(clientEph, eph.Public, sid, chanIdx), false)
	conn, err := newConn(ws, keys.TxKey, keys.RxKey, h.cfg.Pad)
	if err != nil {
		ws.Close()
		return
	}

	// Attach to the bonded tunnel and block until THIS channel dies, so the
	// HTTP/WebSocket goroutine lives exactly as long as its connection.
	done := sess.tun.addChannel(chanIdx, conn)
	<-done
}

// checkAuth validates the PSK-HMAC carried in cookies, the freshness window,
// and the replay filter, and extracts the bonding session id + channel index.
// Any failure returns ok=false and the caller serves the decoy — so an attacker
// cannot distinguish a wrong key from a non-Krot endpoint.
func (h *Handler) checkAuth(r *http.Request) (clientEph [32]byte, sid []byte, chanIdx int, ok bool) {
	ekC, err := r.Cookie(cookieEph)
	if err != nil {
		return clientEph, nil, 0, false
	}
	tsC, err := r.Cookie(cookieTS)
	if err != nil {
		return clientEph, nil, 0, false
	}
	auC, err := r.Cookie(cookieAuth)
	if err != nil {
		return clientEph, nil, 0, false
	}
	siC, err := r.Cookie(cookieSID)
	if err != nil {
		return clientEph, nil, 0, false
	}
	ciC, err := r.Cookie(cookieChan)
	if err != nil {
		return clientEph, nil, 0, false
	}
	ekPub, err := decodeKey(ekC.Value)
	if err != nil {
		return clientEph, nil, 0, false
	}
	token, err := decodeKey(auC.Value)
	if err != nil {
		return clientEph, nil, 0, false
	}
	sidBytes, err := unb64(siC.Value)
	if err != nil || len(sidBytes) != 16 {
		return clientEph, nil, 0, false
	}
	ci, err := parseChan(ciC.Value)
	if err != nil || ci < 0 || ci >= maxChannelsPerSession {
		return clientEph, nil, 0, false
	}
	ts, err := strconv.ParseInt(tsC.Value, 10, 64)
	if err != nil {
		return clientEph, nil, 0, false
	}
	now := time.Now().Unix()
	if ts < now-authWindow || ts > now+authWindow {
		return clientEph, nil, 0, false
	}
	want := authToken(h.cfg.PSK, ekPub, ts, h.cfg.Static.Public, sidBytes)
	if !crypto.ConstantTimeEqual(want, token[:]) {
		return clientEph, nil, 0, false
	}
	// The auth token binds the ephemeral key, which is fresh per channel, so the
	// token itself is unique per channel — the replay filter therefore correctly
	// rejects only true replays, not the sibling channels of one bonded session.
	if !h.cfg.Replay.Check(token[:]) {
		return clientEph, nil, 0, false // replayed token
	}
	return ekPub, sidBytes, ci, true
}
