// Command krot-server runs the Krot VPN server.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/server"
)

func main() {
	cfgPath := flag.String("config", "/etc/krot/server.json", "path to server config JSON")
	flag.Parse()

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer srv.Close()

	errc := make(chan error, 1)
	go func() { errc <- srv.Run() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		log.Printf("server stopped: %v", err)
	case s := <-sig:
		log.Printf("received %s, shutting down...", s)
	}
	// deferred srv.Close() reverts NAT and removes the TUN device.
}
