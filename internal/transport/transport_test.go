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
	done := make(chan error, 1)
	addr, pub := startServer(t, psk, func(c *Tunnel, _ Assignment) {
		got := 0
		for {
			_, err := c.ReadPacket()
			if err != nil {
				if got >= totalData {
					done <- nil
				} else {
					done <- err
				}
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
	conn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server side error (AEAD desync?): %v", err)
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
	if n := tun.channelCount(); n != 4 {
		t.Fatalf("expected 4 channels, got %d", n)
	}

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

	// Forcibly drop 3 of the 4 channels by closing their conns directly.
	tun.mu.Lock()
	killed := 0
	for idx, c := range tun.channels {
		if killed >= 3 {
			break
		}
		_ = idx
		c.Close()
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
