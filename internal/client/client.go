// Package client dials a Krot server, brings up a local TUN device with the
// assigned address, routes the default route through the tunnel, and pumps IP
// packets in both directions.
package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/netif"
	"github.com/krot-vpn/krot/internal/socks"
	"github.com/krot-vpn/krot/internal/transport"
	"github.com/krot-vpn/krot/internal/tun"
)

// hostIP strips a "/prefix" from a CIDR, returning the bare address.
func hostIP(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

// Run establishes the tunnel and runs until ctx is cancelled or a fatal pump
// error occurs. All OS-level changes are reverted before it returns.
func Run(ctx context.Context, cfg *config.Client) error {
	psk, err := config.DecodePSK(cfg.PSK)
	if err != nil {
		return err
	}
	serverPub, err := config.DecodeKey32(cfg.ServerPub)
	if err != nil {
		return err
	}

	serverAddr := net.JoinHostPort(cfg.ServerIP, strconv.Itoa(cfg.ServerPort))
	log.Printf("connecting to %s (sni=%s)...", serverAddr, cfg.SNI)
	conn, assign, err := transport.Dial(transport.ClientConfig{
		ServerAddr:   serverAddr,
		SNI:          cfg.SNI,
		Path:         cfg.Path,
		PSK:          psk,
		ServerStatic: serverPub,
		Insecure:     cfg.Insecure,
		PinSHA256:    cfg.PinSHA256,
		Channels:     cfg.Channels,
	})
	if err != nil {
		return err
	}
	if assign.Addr == "" {
		conn.Close()
		return fmt.Errorf("server did not assign a tunnel address")
	}
	log.Printf("tunnel up: addr=%s gw=%s dns=%s", assign.Addr, assign.Gw, assign.DNS)

	dev, err := tun.Open(cfg.TunName)
	if err != nil {
		conn.Close()
		return err
	}
	if err := netif.IfUp(dev.Name, assign.Addr, cfg.MTU); err != nil {
		dev.Close()
		conn.Close()
		return fmt.Errorf("configure tun: %w", err)
	}

	// LIFO teardown: (routes,) then close TUN, then close tunnel.
	defer conn.Close()
	defer dev.Close()

	socksMode := cfg.SocksListen != ""
	if socksMode {
		// SOCKS chaining mode: bring up the TUN, install source-based policy
		// routing for the TUN address, and expose a SOCKS5 proxy whose outbound
		// sockets are bound to that address — so everything the proxy forwards
		// egresses through the tunnel. Point xray's outbound at this SOCKS and
		// the whole host is untouched (default route/DNS stay as they were).
		srcIP := hostIP(assign.Addr)
		sr, err := netif.SetupSourceRoute(srcIP, dev.Name, cfg.SocksTable)
		if err != nil {
			dev.Close()
			conn.Close()
			return fmt.Errorf("source route setup: %w", err)
		}
		defer sr.Teardown()

		dns := cfg.DNS
		if dns == "" {
			dns = assign.DNS
		}
		sv, err := socks.New(cfg.SocksListen, srcIP, dns)
		if err != nil {
			sr.Teardown()
			dev.Close()
			conn.Close()
			return fmt.Errorf("socks: %w", err)
		}
		defer sv.Close()
		socks.LogStart(sv.Addr(), srcIP)
		go func() {
			if err := sv.Serve(); err != nil {
				// listener closed on shutdown is expected; log others.
				log.Printf("socks server stopped: %v", err)
			}
		}()
	} else if cfg.RouteMode == "manual" {
		// Manual mode: bring up the TUN device only; do NOT touch the default
		// route or DNS. The operator points selected traffic at the TUN via
		// their own policy-routing. This lets krot be a chained uplink
		// without hijacking the whole host.
		log.Printf("route_mode=manual: TUN %s up at %s; routing left to operator", dev.Name, assign.Addr)
	} else {
		dns := cfg.DNS
		if dns == "" {
			dns = assign.DNS
		}
		routes, err := netif.SetupClientRoutes(cfg.ServerIP, dev.Name, dns)
		if err != nil {
			dev.Close()
			conn.Close()
			return fmt.Errorf("route setup: %w", err)
		}
		defer routes.Teardown()
	}

	errc := make(chan error, 2)

	go func() { // TUN -> tunnel
		buf := make([]byte, cfg.MTU+256)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errc <- fmt.Errorf("tun read: %w", err)
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			if err := conn.WritePacket(pkt); err != nil {
				errc <- fmt.Errorf("tunnel write: %w", err)
				return
			}
		}
	}()

	go func() { // tunnel -> TUN
		for {
			pkt, err := conn.ReadPacket()
			if err != nil {
				errc <- fmt.Errorf("tunnel read: %w", err)
				return
			}
			if _, err := dev.Write(pkt); err != nil {
				errc <- fmt.Errorf("tun write: %w", err)
				return
			}
		}
	}()

	stop := make(chan struct{})
	go keepalive(conn, stop)
	defer close(stop)

	if cfg.RouteMode != "manual" && !socksMode {
		log.Printf("routing all traffic through %s", dev.Name)
	}
	select {
	case <-ctx.Done():
		log.Printf("shutting down, restoring network...")
		return nil
	case err := <-errc:
		log.Printf("connection error, restoring network...")
		return err
	}
}

func keepalive(conn *transport.Tunnel, stop chan struct{}) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := conn.WriteKeepalive(); err != nil {
				// Tear the tunnel down so the read/write pumps error out and
				// Run() returns — letting systemd restart a dead client.
				conn.Close()
				return
			}
		}
	}
}
