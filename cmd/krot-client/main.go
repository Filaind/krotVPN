// Command krot-client runs the Krot VPN client in TUN mode.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/krot-vpn/krot/internal/client"
	"github.com/krot-vpn/krot/internal/config"
)

func main() {
	cfgPath := flag.String("config", "/etc/krot/client.json", "path to client config JSON")
	flag.Parse()

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := client.Run(ctx, cfg); err != nil {
		log.Fatalf("client: %v", err)
	}
	log.Printf("stopped cleanly")
}
