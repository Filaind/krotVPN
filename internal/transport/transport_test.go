package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krot-vpn/krot/internal/crypto"
)

// genCert mints an in-memory self-signed cert for the test TLS server. ECDSA
// P-256 matches what the uTLS Chrome ClientHello will accept.
func genCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// startServer launches a Krot handler over a real TLS listener on loopback.
// onConn defaults to an echo loop. It returns the dial address and the server
// static public key.
func startServer(t *testing.T, psk []byte, onConn func(*Tunnel, Assignment)) (addr string, serverPub [32]byte) {
	t.Helper()
	static, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if onConn == nil {
		onConn = func(c *Tunnel, _ Assignment) {
			for {
				p, err := c.ReadPacket()
				if err != nil {
					return
				}
				if err := c.WritePacket(p); err != nil {
					return
				}
			}
		}
	}
	handler, err := NewHandler(HandlerConfig{
		PSK:    psk,
		Static: static,
		Path:   "/api/v2/stream",
		Gw:     "10.8.0.1",
		DNS:    "1.1.1.1",
		Alloc: func() (string, func(), bool) {
			return "10.8.0.2/24", func() {}, true
		},
		OnConn: onConn,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:      handler,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{genCert(t)}},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln.Addr().String(), static.Public
}

func TestTunnelRoundTrip(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	conn, assign, err := Dial(ClientConfig{
		ServerAddr:   addr,
		SNI:          "localhost",
		Path:         "/api/v2/stream",
		PSK:          psk,
		ServerStatic: pub,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if assign.Addr != "10.8.0.2/24" || assign.Gw != "10.8.0.1" {
		t.Fatalf("unexpected assignment: %+v", assign)
	}

	// Send enough packets to exercise the padding burst and steady state.
	for i := 0; i < 30; i++ {
		msg := []byte{byte(i), 0xde, 0xad, 0xbe, 0xef}
		if err := conn.WritePacket(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, err := conn.ReadPacket()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(got) != len(msg) || got[0] != byte(i) || got[4] != 0xef {
			t.Fatalf("echo mismatch at %d: got %x want %x", i, got, msg)
		}
	}
}

func TestWrongPSKHitsDecoy(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	wrong := make([]byte, crypto.KeySize)
	crypto.Random(wrong)

	_, _, err := Dial(ClientConfig{
		ServerAddr:   addr,
		SNI:          "localhost",
		Path:         "/api/v2/stream",
		PSK:          wrong, // wrong key -> server serves decoy, no WS upgrade
		ServerStatic: pub,
		Insecure:     true,
	})
	if err == nil {
		t.Fatal("expected dial to fail with wrong PSK")
	}
}

func TestDecoyServedToPlainClient(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, _ := startServer(t, psk, nil)

	// A plain HTTPS GET (an active probe) must get an ordinary web response.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("probe get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Fatal("probe got empty body; decoy should serve content")
	}
}

// TestConcurrentWritersNoAEADDesync hammers a tunnel with many concurrent
// writer goroutines plus keepalives. Before the seal-under-lock fix this raced
// the AEAD nonce counter (run with -race) and desynced the stream, surfacing as
// "chacha20poly1305: message authentication failed" on the peer. It must now
// run clean: every sealed frame opens in order.
func TestConcurrentWritersNoAEADDesync(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)

	const totalData = 4000
	type result struct {
		got int
		err error
	}
	done := make(chan result, 1)
	addr, pub := startServer(t, psk, func(c *Tunnel, _ Assignment) {
		got := 0
		for {
			_, err := c.ReadPacket()
			if err != nil {
				done <- result{got, err}
				return
			}
			got++
		}
	})

	conn, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	const writers = 8
	per := totalData / writers
	var wg sync.WaitGroup

	// keepalive goroutine racing the data writers — the original trigger.
	stopKA := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopKA:
				return
			default:
				_ = conn.WriteKeepalive()
			}
		}
	}()

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkt := []byte{byte(id), 1, 2, 3, 4, 5, 6, 7}
			for i := 0; i < per; i++ {
				if err := conn.WritePacket(pkt); err != nil {
					t.Errorf("writer %d: %v", id, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stopKA)
	conn.Close() // flushes the channel queue before closing

	select {
	case r := <-done:
		// An AEAD desync surfaces as an authentication failure before the
		// clean close; a tunnel that stays in sync delivers every packet that
		// was not tail-dropped on the (never-blocking) send queue.
		if r.err != nil && strings.Contains(r.err.Error(), "authentication") {
			t.Fatalf("server side AEAD desync: %v", r.err)
		}
		if dropped := int(conn.Dropped()); r.got+dropped != totalData {
			t.Fatalf("server got %d + dropped %d != sent %d (last err: %v)", r.got, dropped, totalData, r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for server to drain")
	}
}

// TestCloseUnblocksReader verifies the mechanism the dead-peer cleanup relies
// on: a ReadPacket blocked with no incoming data must return promptly once
// another goroutine calls Close (as keepalive/dispatch now do on write error).
func TestCloseUnblocksReader(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil) // echo server; sends nothing unsolicited

	conn, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		conn.Close()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacket() // blocks: nothing to read until Close
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected ReadPacket to error after Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadPacket did not unblock after Close")
	}
}

// TestBondedTunnelRoundTrip brings up a 4-channel bonded tunnel against an echo
// server and verifies all packets survive striping across channels and merging
// back. The server groups the 4 channels by session id into one *Tunnel.
func TestBondedTunnelRoundTrip(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil) // echo

	tun, assign, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true, Channels: 4,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	if assign.Addr != "10.8.0.2/24" {
		t.Fatalf("unexpected assignment: %+v", assign)
	}
	waitChannels(t, tun, 4, 5*time.Second)

	// Send many packets; echo must return all of them (order may differ across
	// channels, so match by a per-packet id, not by sequence).
	const N = 400
	sent := make([]bool, N)
	for i := 0; i < N; i++ {
		if err := tun.WritePacket([]byte{byte(i), byte(i >> 8), 0xAB}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := 0
	deadline := time.After(15 * time.Second)
	for got < N {
		type rr struct {
			p   []byte
			err error
		}
		ch := make(chan rr, 1)
		go func() { p, err := tun.ReadPacket(); ch <- rr{p, err} }()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("read: %v (got %d/%d)", r.err, got, N)
			}
			if len(r.p) == 3 && r.p[2] == 0xAB {
				id := int(r.p[0]) | int(r.p[1])<<8
				if id >= 0 && id < N && !sent[id] {
					sent[id] = true
					got++
				}
			}
		case <-deadline:
			t.Fatalf("timeout: only %d/%d packets echoed back", got, N)
		}
	}
}

// TestBondSurvivesChannelLoss verifies the tunnel stays usable after some
// channels die: kill all-but-one by closing the underlying conns, then confirm
// echo still works on the survivor.
func TestBondSurvivesChannelLoss(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	tun, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true, Channels: 4,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	waitChannels(t, tun, 4, 5*time.Second)

	// Forcibly drop 3 of the 4 channels by closing their conns directly.
	tun.mu.Lock()
	killed := 0
	for idx, c := range tun.channels {
		if killed >= 3 {
			break
		}
		_ = idx
		c.c.Close()
		killed++
	}
	tun.mu.Unlock()

	// Give the read loops a moment to notice and deregister.
	time.Sleep(300 * time.Millisecond)
	if n := tun.channelCount(); n == 0 {
		t.Fatal("tunnel died entirely; expected ≥1 surviving channel")
	}

	// Echo must still work on the surviving channel(s).
	if err := tun.WritePacket([]byte{0x01, 0x02, 0xCD}); err != nil {
		t.Fatalf("write after channel loss: %v", err)
	}
	ch := make(chan []byte, 1)
	go func() { p, _ := tun.ReadPacket(); ch <- p }()
	select {
	case p := <-ch:
		if len(p) != 3 || p[2] != 0xCD {
			t.Fatalf("bad echo after channel loss: %x", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no echo after channel loss")
	}
}

// waitChannels waits until the tunnel has exactly want channels attached.
func waitChannels(t *testing.T, tun *Tunnel, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		n := tun.channelCount()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d channels, have %d after %s", want, n, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// reader drains a tunnel into a channel for the rest of the test (one reader
// per tunnel: a second concurrent ReadPacket caller would steal packets).
func reader(tun *Tunnel) <-chan []byte {
	ch := make(chan []byte, 64)
	go func() {
		for {
			p, err := tun.ReadPacket()
			if err != nil {
				close(ch)
				return
			}
			ch <- p
		}
	}()
	return ch
}

// echoOnce sends a marked packet (resending every 200 ms, since one written
// onto a channel that is just dying is lost like on a real link) until the
// echo comes back.
func echoOnce(t *testing.T, tun *Tunnel, in <-chan []byte, mark byte) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := tun.WritePacket([]byte{0x01, 0x02, mark}); err != nil {
			t.Fatalf("write: %v", err)
		}
		select {
		case p := <-in:
			if len(p) == 3 && p[2] == mark {
				return
			}
		case <-tick.C:
		case <-deadline:
			t.Fatalf("no echo for mark %#x", mark)
		}
	}
}

// waitBelow waits until fewer than n channels are attached.
func waitBelow(t *testing.T, tun *Tunnel, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for tun.channelCount() >= n {
		if time.Now().After(deadline) {
			t.Fatalf("channels did not drop below %d", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// killChannels closes the conns of up to k attached channels (k<0: all), as a
// stalled TCP connection being killed by TCP_USER_TIMEOUT would.
func killChannels(tun *Tunnel, k int) {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	for _, c := range tun.channels {
		if k == 0 {
			return
		}
		c.c.Close()
		k--
	}
}

// TestChannelsRedialAfterLoss: channels that die are redialed and rejoin the
// same session, so the tunnel returns to full strength without a restart.
func TestChannelsRedialAfterLoss(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	tun, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true, Channels: 4,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	waitChannels(t, tun, 4, 5*time.Second)
	in := reader(tun)

	for round := 0; round < 5; round++ { // several generations exercise wireIndex rotation
		killChannels(tun, 3)
		waitBelow(t, tun, 4)
		waitChannels(t, tun, 4, 5*time.Second)
		echoOnce(t, tun, in, byte(0xD0+round))
	}
}

// TestTunnelSurvivesLosingAllChannels: a client tunnel with no channel left
// stays open (dropping packets) while its maintainers redial, then carries
// traffic again.
func TestTunnelSurvivesLosingAllChannels(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	tun, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true, Channels: 2,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	waitChannels(t, tun, 2, 5*time.Second)
	in := reader(tun)

	killChannels(tun, -1)
	waitBelow(t, tun, 1)
	if err := tun.WritePacket([]byte{0x01, 0x02, 0x00}); err != nil {
		t.Fatalf("write while redialing must not fail: %v", err)
	}
	if tun.isClosed() {
		t.Fatal("tunnel died with its channels")
	}
	waitChannels(t, tun, 2, 5*time.Second)
	echoOnce(t, tun, in, 0xE2)
}

// TestRejoinWithNewAddressClosesTunnel: if the server lost the session and
// hands a redialed channel a different address, the tunnel must die so the
// client restarts with the new address instead of sending from the old one.
func TestRejoinWithNewAddressClosesTunnel(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	static, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	next := 2
	handler, err := NewHandler(HandlerConfig{
		PSK: psk, Static: static, Path: "/api/v2/stream", Gw: "10.8.0.1",
		Alloc: func() (string, func(), bool) {
			mu.Lock()
			defer mu.Unlock()
			a := next
			next++
			return "10.8.0." + string(rune('0'+a)) + "/24", func() {}, true
		},
		OnConn: func(c *Tunnel, _ Assignment) {
			for {
				if _, err := c.ReadPacket(); err != nil {
					return
				}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:      handler,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{genCert(t)}},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go srv.ServeTLS(ln, "", "")
	defer func() { srv.Close(); ln.Close() }()

	tun, assign, err := Dial(ClientConfig{
		ServerAddr: ln.Addr().String(), SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: static.Public, Insecure: true, Channels: 1,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	if assign.Addr != "10.8.0.2/24" {
		t.Fatalf("unexpected first address %s", assign.Addr)
	}
	waitChannels(t, tun, 1, 5*time.Second)

	// Killing the only channel empties the server session; the rejoin creates
	// a new one with the next address.
	killChannels(tun, -1)
	select {
	case <-tun.dead:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel kept running after the server changed its address")
	}
}

// TestReplacementKeepsFlowPositions: replacing one channel must not move the
// flows pinned to the others (a reshuffle would reorder every inner flow).
func TestReplacementKeepsFlowPositions(t *testing.T) {
	psk := make([]byte, crypto.KeySize)
	crypto.Random(psk)
	addr, pub := startServer(t, psk, nil)

	tun, _, err := Dial(ClientConfig{
		ServerAddr: addr, SNI: "localhost", Path: "/api/v2/stream",
		PSK: psk, ServerStatic: pub, Insecure: true, Channels: 4,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	waitChannels(t, tun, 4, 5*time.Second)

	tun.mu.Lock()
	before := append([]int(nil), tun.slots...)
	victim := tun.channels[before[1]]
	others := map[int]*channel{}
	for _, p := range []int{0, 2, 3} {
		others[p] = tun.channels[before[p]]
	}
	tun.mu.Unlock()

	victim.c.Close()
	waitBelow(t, tun, 4)
	tun.mu.Lock()
	if tun.slots[1] != -1 {
		t.Fatalf("dead channel's position not emptied: %v", tun.slots)
	}
	tun.mu.Unlock()
	waitChannels(t, tun, 4, 5*time.Second)

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.slots) != 4 {
		t.Fatalf("positions grew: %v", tun.slots)
	}
	for p, ch := range others {
		if tun.channels[tun.slots[p]] != ch {
			t.Fatalf("position %d changed channel after an unrelated replacement", p)
		}
	}
	if tun.channels[tun.slots[1]] == victim {
		t.Fatal("dead channel still in place")
	}
}
