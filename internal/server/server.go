// Package server wires the Krot transport to a TUN device and the OS network
// stack: it terminates TLS, authenticates clients, assigns tunnel addresses,
// and forwards client IP packets to the internet via NAT.
package server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/crypto"
	"github.com/krot-vpn/krot/internal/netif"
	"github.com/krot-vpn/krot/internal/transport"
	"github.com/krot-vpn/krot/internal/tun"
)

// Server is the running Krot server.
type Server struct {
	cfg    *config.Server
	psk    []byte
	static crypto.Keypair
	dev    *tun.Device
	nat    *netif.NATState
	pool   *ipPool
	gw     string

	mu       sync.RWMutex
	sessions map[uint32]*transport.Tunnel
}

// New brings up the TUN device, NAT, and address pool.
func New(cfg *config.Server) (*Server, error) {
	psk, err := config.DecodePSK(cfg.PSK)
	if err != nil {
		return nil, err
	}
	priv, err := config.DecodeKey32(cfg.ServerPriv)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.PublicFromPrivate(priv)
	if err != nil {
		return nil, err
	}
	pool, err := newIPPool(cfg.TunCIDR)
	if err != nil {
		return nil, err
	}
	gwIP, _, err := net.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		return nil, err
	}

	dev, err := tun.Open(cfg.TunName)
	if err != nil {
		return nil, err
	}
	if err := netif.IfUp(dev.Name, cfg.TunCIDR, cfg.MTU); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure tun: %w", err)
	}
	nat, err := netif.SetupServerNAT(dev.Name, cfg.TunCIDR, cfg.WANIface)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("nat setup: %w", err)
	}

	return &Server{
		cfg:      cfg,
		psk:      psk,
		static:   crypto.Keypair{Private: priv, Public: pub},
		dev:      dev,
		nat:      nat,
		pool:     pool,
		gw:       gwIP.String(),
		sessions: make(map[uint32]*transport.Tunnel),
	}, nil
}

// Run starts the TUN dispatcher and the HTTPS listener. It blocks.
func (s *Server) Run() error {
	go s.dispatch()

	handler, err := transport.NewHandler(transport.HandlerConfig{
		PSK:    s.psk,
		Static: s.static,
		Path:   s.cfg.Path,
		Gw:     s.gw,
		DNS:    s.cfg.DNS,
		Decoy:  s.cfg.Decoy,
		// Replay filter is created with the correct TTL inside NewHandler.
		Alloc: func() (string, func(), bool) {
			cidr, _, release, ok := s.pool.alloc()
			return cidr, release, ok
		},
		OnConn: s.handleConn,
	})
	if err != nil {
		return err
	}

	tlsCfg, err := s.tlsConfig()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("krot server listening on %s (sni=%s path=%s)", s.cfg.Listen, s.cfg.SNI, s.cfg.Path)
	// Terminate TLS via our own listener whose ALPN offers ONLY http/1.1. A
	// real Chrome client still advertises h2+http/1.1 (authentic fingerprint),
	// but negotiation is forced to http/1.1 — required by the WebSocket
	// transport. Using http.Server.ListenAndServeTLS instead re-adds "h2" to
	// the ALPN list, after which net/http silently drops the negotiated-h2
	// connection (no h2 handler is registered) and the client sees EOF.
	return srv.Serve(tls.NewListener(ln, tlsCfg))
}

// Close tears down OS-level state.
func (s *Server) Close() {
	if s.nat != nil {
		s.nat.Teardown()
	}
	if s.dev != nil {
		s.dev.Close()
	}
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if s.cfg.SelfSigned {
		cert, err = selfSignedCert(s.cfg.SNI)
	} else {
		cert, err = tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13, // ensures the cert message is encrypted
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert},
	}, nil
}

// handleConn services one authenticated bonded tunnel for its lifetime.
func (s *Server) handleConn(tun *transport.Tunnel, assign transport.Assignment) {
	ip, ok := parseHostIP(assign.Addr)
	if !ok {
		return
	}
	s.register(ip, tun)
	defer s.unregister(ip, tun)

	stop := make(chan struct{})
	go keepalive(tun, stop)
	defer close(stop)

	for {
		pkt, err := tun.ReadPacket()
		if err != nil {
			return
		}
		if _, err := s.dev.Write(pkt); err != nil {
			return
		}
	}
}

func keepalive(tun *transport.Tunnel, stop chan struct{}) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := tun.WriteKeepalive(); err != nil {
				// All channels gone: tear the tunnel down so the blocked
				// reader (handleConn) unblocks and frees its pool address.
				tun.Close()
				return
			}
		}
	}
}

// dispatch reads reply packets from the TUN and routes each to the client that
// owns its destination address.
func (s *Server) dispatch() {
	buf := make([]byte, s.cfg.MTU+256)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		dst, ok := ipv4Dst(buf[:n])
		if !ok {
			continue
		}
		s.mu.RLock()
		tun := s.sessions[dst]
		s.mu.RUnlock()
		if tun == nil {
			continue
		}
		p := make([]byte, n)
		copy(p, buf[:n])
		if err := tun.WritePacket(p); err != nil {
			// All channels broken: close so handleConn's reader errors out,
			// frees the pool address, and we stop spending work on a dead peer.
			tun.Close()
		}
	}
}

func (s *Server) register(ip uint32, tun *transport.Tunnel) {
	// Each live session owns a unique address from the pool for its whole
	// lifetime, so there is never a prior tunnel registered under this ip. (If
	// the pool ever hands out an address while an old session still holds it,
	// this invariant must be revisited.)
	s.mu.Lock()
	s.sessions[ip] = tun
	s.mu.Unlock()
}

func (s *Server) unregister(ip uint32, tun *transport.Tunnel) {
	s.mu.Lock()
	if s.sessions[ip] == tun {
		delete(s.sessions, ip)
	}
	s.mu.Unlock()
}

// ipv4Dst extracts the destination address of an IPv4 packet.
func ipv4Dst(p []byte) (uint32, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(p[16:20]), true
}

// parseHostIP turns "10.8.0.5/24" or "10.8.0.5" into its uint32 form.
func parseHostIP(cidr string) (uint32, bool) {
	host := cidr
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			host = cidr[:i]
			break
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}
