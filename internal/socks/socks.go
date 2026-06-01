// Package socks implements a minimal SOCKS5 server (CONNECT only) whose
// outbound connections are pinned to a given source IP — the Krot TUN
// address — so that the host's source-based policy routing sends them through
// the tunnel. This lets Krot act as a chained uplink for proxies such as
// xray: point xray's outbound at socks://127.0.0.1:1080 and everything it
// sends egresses via the EU Krot server, with no fwmark/route fiddling on
// the operator's side.
//
// Hostnames in CONNECT requests are resolved through a resolver that is also
// pinned to the TUN source IP and aimed at the tunnel's DNS server, so DNS
// does not leak around the tunnel.
package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	ver5         = 0x05
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
	repSucceeded = 0x00
	repGenFail   = 0x01
	repNotAllow  = 0x02
	repHostUnrch = 0x04
	repCmdNotSup = 0x07
)

// Server is a SOCKS5 CONNECT proxy that egresses via a fixed source IP.
type Server struct {
	ln       net.Listener
	dialer   *net.Dialer
	resolver *net.Resolver
}

// New binds a SOCKS5 listener on listenAddr. Outbound connections use srcIP as
// their local address; dnsAddr (host or host:port, :53 default) is used for
// name resolution, itself dialed from srcIP. Pass srcIP="" to use the default
// source (no pinning) and dnsAddr="" to use the system resolver.
func New(listenAddr, srcIP, dnsAddr string) (*Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("socks listen %s: %w", listenAddr, err)
	}

	var localTCP *net.TCPAddr
	if srcIP != "" {
		ip := net.ParseIP(srcIP)
		if ip == nil {
			ln.Close()
			return nil, fmt.Errorf("socks: bad srcIP %q", srcIP)
		}
		localTCP = &net.TCPAddr{IP: ip}
	}

	d := &net.Dialer{Timeout: 12 * time.Second, LocalAddr: localTCP}

	res := net.DefaultResolver
	if dnsAddr != "" {
		if _, _, err := net.SplitHostPort(dnsAddr); err != nil {
			dnsAddr = net.JoinHostPort(dnsAddr, "53")
		}
		// Resolver dials the DNS server pinned to the same source IP, so lookups
		// travel through the tunnel.
		rd := &net.Dialer{Timeout: 8 * time.Second, LocalAddr: udpLocal(localTCP)}
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				n := "udp"
				if network == "tcp" || network == "tcp4" || network == "tcp6" {
					n = "tcp"
				}
				return rd.DialContext(ctx, n, dnsAddr)
			},
		}
	}
	d.Resolver = res

	return &Server{ln: ln, dialer: d, resolver: res}, nil
}

func udpLocal(t *net.TCPAddr) *net.UDPAddr {
	if t == nil {
		return nil
	}
	return &net.UDPAddr{IP: t.IP}
}

// Addr returns the listening address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// Close stops the server.
func (s *Server) Close() error { return s.ln.Close() }

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	target, err := s.handshake(c)
	if err != nil {
		return
	}

	remote, err := s.dialer.Dial("tcp", target)
	if err != nil {
		_ = sendReply(c, replyCodeFor(err))
		return
	}
	defer remote.Close()

	if err := sendReply(c, repSucceeded); err != nil {
		return
	}
	// Connected: clear deadlines and pump bidirectionally.
	_ = c.SetDeadline(time.Time{})
	relay(c, remote)
}

// handshake performs the SOCKS5 greeting + CONNECT request, returning the
// "host:port" target to dial.
func (s *Server) handshake(c net.Conn) (string, error) {
	// greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", err
	}
	if hdr[0] != ver5 {
		return "", errors.New("socks: not v5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	// reply: no-auth
	if _, err := c.Write([]byte{ver5, 0x00}); err != nil {
		return "", err
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", err
	}
	if req[0] != ver5 {
		return "", errors.New("socks: bad request version")
	}
	if req[1] != cmdConnect {
		_ = sendReply(c, repCmdNotSup)
		return "", errors.New("socks: only CONNECT supported")
	}

	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		_ = sendReply(c, repCmdNotSup)
		return "", errors.New("socks: bad ATYP")
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	port := int(pb[0])<<8 | int(pb[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// sendReply writes a SOCKS5 reply with the given code and a zero BND.ADDR.
func sendReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{ver5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func replyCodeFor(err error) byte {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return repHostUnrch
	}
	return repGenFail
}

// relay copies data in both directions until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// half-close so the peer sees EOF
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// LogStart is a tiny helper so the client can log a consistent line.
func LogStart(addr net.Addr, srcIP string) {
	log.Printf("socks5 listening on %s (egress src=%s -> krot tunnel)", addr, srcIP)
}
