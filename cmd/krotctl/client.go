package main

import (
	"context"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/krot-vpn/krot/internal/client"
	"github.com/krot-vpn/krot/internal/config"
)

// Client instances are keyed by -name so several krot clients can coexist on
// one host (e.g. a WG uplink + an xray-socks uplink, as on the .85 gateway).
// Each gets its own config file, systemd instance, TUN device, and (in socks
// mode) policy-routing table.

func clientCfgPath(name string) string {
	return fmt.Sprintf("/etc/krot/client-%s.json", name)
}

const clientUnitTemplatePath = "/etc/systemd/system/krot-client@.service"

func clientUnit(name string) string { return "krot-client@" + name }

func cmdClient(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("client: need a subcommand (up|run|status|down)")
	}
	switch args[0] {
	case "up":
		return clientUp(args[1:])
	case "run":
		return clientRun(args[1:])
	case "status":
		return clientStatus(args[1:])
	case "down":
		return clientDown(args[1:])
	default:
		return fmt.Errorf("client: unknown subcommand %q", args[0])
	}
}

func clientUp(args []string) error {
	fs := flag.NewFlagSet("client up", flag.ExitOnError)
	name := fs.String("name", "default", "instance name (allows several clients on one host)")
	mode := fs.String("mode", "full", "routing mode: full | socks | manual")
	server := fs.String("server", "", "server IP to dial (required)")
	port := fs.Int("port", 443, "server port")
	sni := fs.String("sni", "", "TLS server name (required)")
	path := fs.String("path", "", "secret WebSocket path (required)")
	psk := fs.String("psk", "", "base64 PSK (required)")
	pub := fs.String("server-pub", "", "base64 server public key (required)")
	insecure := fs.Bool("insecure", true, "skip cert verification (self-signed servers)")
	pin := fs.String("pin-sha256", "", "optional base64 SHA-256 of server cert SPKI")
	tunName := fs.String("tun-name", "", "TUN device name (default krot-<name>, capped to 15 chars)")
	mtu := fs.Int("mtu", 1320, "tunnel MTU (must match server)")
	channels := fs.Int("channels", 4, "bonded parallel channels")
	dns := fs.String("dns", "", "DNS override (default: server-provided)")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "socks mode: SOCKS5 listen address")
	socksTable := fs.String("socks-table", "", "socks mode: policy-routing table (default: derived from name)")
	force := fs.Bool("force", false, "overwrite existing instance config")
	noStart := fs.Bool("no-start", false, "write config + unit but don't start")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (TUN/routing/systemd)")
	}
	switch *mode {
	case "full", "socks", "manual":
	default:
		return fmt.Errorf("bad -mode %q (full|socks|manual)", *mode)
	}
	for k, v := range map[string]string{"server": *server, "sni": *sni, "path": *path, "psk": *psk, "server-pub": *pub} {
		if v == "" {
			return fmt.Errorf("-%s is required", k)
		}
	}
	cfgPath := clientCfgPath(*name)
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; use -force", cfgPath)
	}

	tn := *tunName
	if tn == "" {
		tn = tunDevName(*name)
	}
	tbl := *socksTable
	if tbl == "" {
		tbl = tableFor(*name)
	}

	cfg := &config.Client{
		ServerIP: *server, ServerPort: *port, SNI: *sni, Path: *path,
		PSK: *psk, ServerPub: *pub, Insecure: *insecure, PinSHA256: *pin,
		TunName: tn, MTU: *mtu, Channels: *channels, DNS: *dns,
	}
	switch *mode {
	case "manual":
		cfg.RouteMode = "manual"
	case "socks":
		cfg.SocksListen = *socksAddr
		cfg.SocksTable = tbl
	}
	// Validate by round-tripping through the loader's rules.
	if err := writeClientConfig(cfgPath, cfg); err != nil {
		return err
	}
	if _, err := config.LoadClient(cfgPath); err != nil {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("config rejected: %w", err)
	}
	fmt.Printf("wrote %s (mode=%s tun=%s)\n", cfgPath, *mode, tn)

	if err := installClientUnitTemplate(); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", clientUnitTemplatePath)

	if *noStart {
		fmt.Printf("(-no-start) start later: systemctl start %s\n", clientUnit(*name))
		return nil
	}
	if err := sh("systemctl", "daemon-reload"); err != nil {
		return err
	}
	_ = sh("systemctl", "enable", clientUnit(*name))
	if err := sh("systemctl", "restart", clientUnit(*name)); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	fmt.Printf("\nclient '%s' started. status: %s\n", *name, svcActive(clientUnit(*name)))
	if *mode == "socks" {
		fmt.Printf("SOCKS5 proxy: %s  (point xray's outbound here)\n", *socksAddr)
	}
	return nil
}

// clientRun runs one client instance in the foreground (systemd ExecStart).
func clientRun(args []string) error {
	fs := flag.NewFlagSet("client run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to client config JSON (required)")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		return fmt.Errorf("-config is required")
	}
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return client.Run(ctx, cfg)
}

func clientStatus(args []string) error {
	fs := flag.NewFlagSet("client status", flag.ExitOnError)
	name := fs.String("name", "default", "instance name")
	_ = fs.Parse(args)

	unit := clientUnit(*name)
	fmt.Printf("instance  : %s\n", *name)
	fmt.Printf("service   : %s\n", svcActive(unit))

	cfg, err := config.LoadClient(clientCfgPath(*name))
	if err != nil {
		fmt.Printf("config    : (not found: %v)\n", err)
		return nil
	}
	printCmd("tun       ", "ip", "-br", "addr", "show", cfg.TunName)
	if cfg.SocksListen != "" {
		if out, err := exec.Command("ss", "-tlnp").Output(); err == nil {
			port := cfg.SocksListen
			if i := strings.LastIndex(port, ":"); i >= 0 {
				port = port[i+1:]
			}
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.Contains(ln, ":"+port+" ") {
					fmt.Printf("socks     : %s\n", strings.TrimSpace(ln))
				}
			}
		}
		printCmd("src-rule  ", "sh", "-c", "ip rule | grep 'lookup "+cfg.SocksTable+"' || echo none")
	}
	return nil
}

func clientDown(args []string) error {
	fs := flag.NewFlagSet("client down", flag.ExitOnError)
	name := fs.String("name", "default", "instance name")
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	if err := sh("systemctl", "stop", clientUnit(*name)); err != nil {
		fmt.Fprintln(os.Stderr, "warn: stop:", err)
	}
	fmt.Printf("stopped %s; routing/TUN reverted by the daemon on exit\n", clientUnit(*name))
	return nil
}

// tunDevName builds a Linux-legal (<=15 char) interface name for an instance.
func tunDevName(name string) string {
	n := "mir-" + name
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

// tableFor derives a stable policy-routing table id (100..355) from the
// instance name, so two socks instances on one host never share a table.
func tableFor(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%d", 100+int(h.Sum32()%256))
}
