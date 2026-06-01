package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/server"
)

const (
	serverCfgPath  = "/etc/krot/server.json"
	serverUnit     = "krot-server"
	serverUnitPath = "/etc/systemd/system/krot-server.service"
)

func cmdServer(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("server: need a subcommand (up|run|status|down)")
	}
	switch args[0] {
	case "up":
		return serverUp(args[1:])
	case "run":
		return serverRun(args[1:])
	case "status":
		return serverStatus()
	case "down":
		return serverDown()
	default:
		return fmt.Errorf("server: unknown subcommand %q", args[0])
	}
}

func serverUp(args []string) error {
	fs := flag.NewFlagSet("server up", flag.ExitOnError)
	sni := fs.String("sni", "en.wikipedia.org", "TLS server name / self-signed CN")
	listen := fs.String("listen", ":443", "bind address")
	decoy := fs.String("decoy", "", "reverse-proxy target for unauthenticated/probe traffic")
	tunCIDR := fs.String("tun-cidr", "10.8.0.1/24", "tunnel subnet (gateway address)")
	tunName := fs.String("tun-name", "krot0", "TUN device name")
	dns := fs.String("dns", "1.1.1.1", "DNS handed to clients")
	wan := fs.String("wan", "", "egress interface for NAT (empty = auto-detect)")
	mtu := fs.Int("mtu", 1320, "tunnel MTU")
	selfSigned := fs.Bool("self-signed", true, "use a throwaway self-signed cert")
	certFile := fs.String("cert", "", "TLS cert chain PEM (disables self-signed)")
	keyFile := fs.String("key", "", "TLS private key PEM")
	psk := fs.String("psk", "", "base64 PSK (generated if empty)")
	priv := fs.String("priv", "", "base64 server static private key (generated if empty)")
	force := fs.Bool("force", false, "overwrite an existing config")
	noStart := fs.Bool("no-start", false, "write config + unit but don't start the service")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (TUN/iptables/systemd)")
	}
	if _, err := os.Stat(serverCfgPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; use -force to overwrite", serverCfgPath)
	}
	if *certFile != "" || *keyFile != "" {
		*selfSigned = false
		if *certFile == "" || *keyFile == "" {
			return fmt.Errorf("-cert and -key must be given together")
		}
	}

	// Always generate a fresh set (for PSK/priv/path defaults); override the
	// PSK/priv with any provided by the operator.
	gen, err := genSecrets()
	if err != nil {
		return err
	}
	pskV, privV := *psk, *priv
	if pskV == "" {
		pskV = gen.PSK
	}
	if privV == "" {
		privV = gen.Priv
	}
	// Derive the public key from priv so we can print client creds.
	privRaw, err := config.DecodeKey32(privV)
	if err != nil {
		return fmt.Errorf("priv: %w", err)
	}
	pubV, err := derivePub(privRaw)
	if err != nil {
		return fmt.Errorf("derive pubkey: %w", err)
	}

	cfg := &config.Server{
		Listen: *listen, SNI: *sni, Path: gen.Path,
		PSK: pskV, ServerPriv: privV,
		CertFile: *certFile, KeyFile: *keyFile, SelfSigned: *selfSigned,
		Decoy: *decoy, TunName: *tunName, TunCIDR: *tunCIDR,
		DNS: *dns, WANIface: *wan, MTU: *mtu,
	}
	if err := writeServerConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", serverCfgPath)

	if err := installServerUnit(); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", serverUnitPath)

	if *noStart {
		fmt.Println("(-no-start) not starting; `systemctl start krot-server` when ready")
		return nil
	}
	if err := sh("systemctl", "daemon-reload"); err != nil {
		return err
	}
	_ = sh("systemctl", "enable", serverUnit)
	if err := sh("systemctl", "restart", serverUnit); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	fmt.Printf("\nserver started. status: %s\n", svcActive(serverUnit))
	fmt.Print("\n# ---- client credentials (put on the client) ----\n")
	fmt.Printf("sni        : %s\n", cfg.SNI)
	fmt.Printf("path       : %s\n", cfg.Path)
	fmt.Printf("psk        : %s\n", cfg.PSK)
	fmt.Printf("server_pub : %s\n", pubV)
	if cfg.SelfSigned {
		fmt.Print("insecure   : true  (self-signed — use a real cert for active-probe resistance)\n")
	}
	return nil
}

// serverRun runs the server in the foreground; this is what the systemd unit
// executes. It blocks until signalled, then reverts networking.
func serverRun(args []string) error {
	fs := flag.NewFlagSet("server run", flag.ExitOnError)
	cfgPath := fs.String("config", serverCfgPath, "path to server config JSON")
	_ = fs.Parse(args)

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("startup: %w", err)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Run() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return nil // deferred Close reverts NAT + TUN
	}
}

func serverStatus() error {
	fmt.Printf("service   : %s\n", svcActive(serverUnit))

	// Read the live config so we report the ACTUAL tun device / listen port /
	// subnet, not hardcoded guesses.
	tunName, listenPort, subnet := "krot0", "443", ""
	if cfg, err := config.LoadServer(serverCfgPath); err == nil {
		tunName = cfg.TunName
		if i := strings.LastIndex(cfg.Listen, ":"); i >= 0 {
			listenPort = cfg.Listen[i+1:]
		}
		subnet = cfg.TunCIDR
	}

	if out, err := exec.Command("ss", "-tlnp").Output(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(ln, ":"+listenPort+" ") {
				fmt.Printf("listener  : %s\n", strings.TrimSpace(ln))
			}
		}
	}
	printCmd("tun       ", "ip", "-br", "addr", "show", tunName)
	if out, err := exec.Command("iptables", "-t", "nat", "-S", "POSTROUTING").Output(); err == nil {
		want := subnetMatch(subnet)
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(ln, "MASQUERADE") && (want == "" || strings.Contains(ln, want)) {
				fmt.Printf("nat       : %s\n", strings.TrimSpace(ln))
			}
		}
	}
	return nil
}

// subnetMatch turns "10.8.0.1/24" into the network "10.8.0.0/24" iptables
// shows in -S output, so status filters to THIS server's NAT rule. Returns ""
// if it can't parse, meaning "match any MASQUERADE".
func subnetMatch(cidr string) string {
	if cidr == "" {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return ipnet.String()
}

func serverDown() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	// Stopping the service triggers the daemon's own Close(), which reverts
	// NAT and removes the TUN device.
	if err := sh("systemctl", "stop", serverUnit); err != nil {
		fmt.Fprintln(os.Stderr, "warn: stop:", err)
	}
	fmt.Printf("stopped %s; networking reverted by the daemon on exit\n", serverUnit)
	return nil
}
