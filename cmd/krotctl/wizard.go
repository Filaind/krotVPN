package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// The wizard is a prompt-based (not full-screen) interactive front-end. It only
// collects answers, then builds the exact same flag list the non-interactive
// `server up` / `client up` commands accept and calls them — so there is one
// code path to apply a deployment, and the wizard can't drift from it. This
// also works fine over SSH and is testable by piping answers on stdin.

type wiz struct{ r *bufio.Reader }

func newWiz() *wiz { return &wiz{r: bufio.NewReader(os.Stdin)} }

// hint prints a dim, indented one-liner explaining a prompt: what it does,
// whether it can be skipped (Enter = default) and what's recommended.
func hint(s string) { fmt.Printf("\033[2m   ↳ %s\033[0m\n", s) }

// ask prints "label [def]: " and returns the trimmed input, or def if empty.
func (w *wiz) ask(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := w.r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// askRequired re-prompts until a non-empty value is given.
func (w *wiz) askRequired(label string) string {
	for {
		if v := w.ask(label, ""); v != "" {
			return v
		}
		fmt.Println("  (required)")
	}
}

// yesNo returns a bool; def is the value for empty input.
func (w *wiz) yesNo(label string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	for {
		fmt.Printf("%s [%s]: ", label, d)
		line, _ := w.r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

// choice returns one of opts; def must be one of them.
func (w *wiz) choice(label string, opts []string, def string) string {
	for {
		v := w.ask(fmt.Sprintf("%s (%s)", label, strings.Join(opts, "/")), def)
		for _, o := range opts {
			if v == o {
				return v
			}
		}
		fmt.Printf("  choose one of: %s\n", strings.Join(opts, ", "))
	}
}

func cmdWizard(args []string) error {
	w := newWiz()
	fmt.Println("Krot interactive setup")
	fmt.Println("========================")
	fmt.Println("Press Enter to accept the [default] shown in brackets. Hints below each")
	fmt.Println("question explain the value and what's recommended.")
	fmt.Println()
	hint("server = the EU exit node you rent; client = the machine that tunnels through it.")
	role := w.choice("Role to configure", []string{"server", "client"}, "server")
	fmt.Println()
	switch role {
	case "server":
		return wizardServer(w)
	case "client":
		return wizardClient(w)
	}
	return nil
}

func wizardServer(w *wiz) error {
	fmt.Println("# Server (EU exit node)")
	fmt.Println("All values have safe defaults — you can press Enter through the whole")
	fmt.Println("setup for a working self-signed server.")
	fmt.Println()
	hint("Domain your TLS traffic impersonates. Keep the default unless you own a real domain; it should look like an ordinary big HTTPS site. (skippable)")
	sni := w.ask("TLS server name (SNI / self-signed CN)", "en.wikipedia.org")
	hint("Where the server listens. :443 = all interfaces on the HTTPS port, which blends in best. Recommended: keep :443. (skippable)")
	listen := w.ask("Listen address", ":443")
	hint("Site shown to anyone who probes the server without valid credentials, so it looks real. Best match your SNI. Blank = built-in placeholder page. (skippable)")
	decoy := w.ask("Decoy URL for probes (blank = built-in page)", "https://en.wikipedia.org")
	hint("Private subnet used inside the tunnel. Default is fine unless it clashes with your existing LAN. (skippable)")
	tunCIDR := w.ask("Tunnel subnet (gateway addr/mask)", "10.8.0.1/24")
	hint("DNS resolver pushed to connected clients. 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google) both work. (skippable)")
	dns := w.ask("DNS handed to clients", "1.1.1.1")
	hint("Tunnel packet size. 1320 is safe on almost every network; lower only if you see fragmentation/stalls. (skippable)")
	mtu := w.ask("Tunnel MTU", "1320")

	args := []string{
		"-sni", sni, "-listen", listen, "-decoy", decoy,
		"-tun-cidr", tunCIDR, "-dns", dns, "-mtu", mtu,
	}

	hint("y = real Let's Encrypt cert (strongest, needs a domain pointing at this server). N = self-signed (instant, works, but weaker against active probing). Recommended: N for a quick start, y for production.")
	if w.yesNo("Use a real TLS cert (Let's Encrypt) instead of self-signed?", false) {
		cert := w.askRequired("  cert chain PEM path")
		key := w.askRequired("  private key PEM path")
		args = append(args, "-cert", cert, "-key", key)
	} else {
		args = append(args, "-self-signed")
	}

	hint("Y = generate a new PSK + server key (recommended for a fresh server). n = paste credentials you already have to reuse them.")
	if !w.yesNo("Generate fresh credentials (PSK + server key)?", true) {
		args = append(args, "-psk", w.askRequired("  existing PSK (base64)"),
			"-priv", w.askRequired("  existing server private key (base64)"))
	}
	if _, err := os.Stat(serverCfgPath); err == nil {
		hint("A config already exists. y = replace it with this new setup. N = keep the current one and abort. Default N is the safe choice.")
		if w.yesNo(fmt.Sprintf("%s exists — overwrite?", serverCfgPath), false) {
			args = append(args, "-force")
		}
	}

	return wizApply("server up", func() error { return serverUp(args) }, append([]string{"server", "up"}, args...))
}

func wizardClient(w *wiz) error {
	fmt.Println("# Client")
	fmt.Println("The five required values (server IP, SNI, path, PSK, server key) come from")
	fmt.Println("the server's setup output — copy them here. The rest have defaults.")
	fmt.Println()
	hint("Label for this connection; lets you run several clients on one host. Keep 'default' if you only need one. (skippable)")
	name := w.ask("Instance name", "default")
	hint("full = route all traffic through the VPN. socks = expose a local SOCKS5 proxy only. manual = set up the tunnel but don't change routing. Recommended: full.")
	mode := w.choice("Routing mode", []string{"full", "socks", "manual"}, "full")
	hint("Public IP (or host) of your krot server. Required — from the server.")
	server := w.askRequired("Server IP to dial")
	hint("Port the server listens on. Match the server's listen port; 443 unless you changed it. (skippable)")
	port := w.ask("Server port", "443")
	hint("Must exactly match the server's SNI. Required — from the server's output ('sni').")
	sni := w.askRequired("TLS server name (SNI)")
	hint("Secret URL path the server expects. Required — from the server's output ('path').")
	path := w.askRequired("Secret WebSocket path")
	hint("Shared secret. Required — from the server's output ('psk').")
	psk := w.askRequired("PSK (base64)")
	hint("Server's public key. Required — from the server's output ('server_pub').")
	pub := w.askRequired("Server public key (base64)")
	hint("Parallel connections bonded for throughput. 4 is a good default; raise for higher bandwidth, lower on flaky links. (skippable)")
	channels := w.ask("Bonded channels", "4")
	hint("Must match the server's MTU. Keep 1320 unless you changed it on the server. (skippable)")
	mtu := w.ask("Tunnel MTU", "1320")
	hint("y = don't verify the TLS cert — needed when the server uses self-signed (the default server setup). n = verify, for a real Let's Encrypt cert. Recommended: y for self-signed servers.")
	insecure := w.yesNo("Skip cert verification (self-signed server)?", true)

	args := []string{
		"-name", name, "-mode", mode, "-server", server, "-port", port,
		"-sni", sni, "-path", path, "-psk", psk, "-server-pub", pub,
		"-channels", channels, "-mtu", mtu,
	}
	if insecure {
		args = append(args, "-insecure")
	} else {
		args = append(args, "-insecure=false")
	}
	if mode == "socks" {
		hint("Local address the SOCKS5 proxy listens on. 127.0.0.1:1080 keeps it private to this machine. (skippable)")
		args = append(args, "-socks", w.ask("SOCKS5 listen address", "127.0.0.1:1080"))
	}
	if _, err := os.Stat(clientCfgPath(name)); err == nil {
		hint("This instance already exists. y = replace it. N = keep the current one and abort. Default N is the safe choice.")
		if w.yesNo(fmt.Sprintf("%s exists — overwrite?", clientCfgPath(name)), false) {
			args = append(args, "-force")
		}
	}

	return wizApply("client up", func() error { return clientUp(args) }, append([]string{"client", "up"}, args...))
}

// wizApply shows the equivalent command, then optionally runs it. If the user
// wants to apply but isn't root, it prints the sudo command instead of failing
// obscurely.
func wizApply(what string, apply func() error, fullArgs []string) error {
	fmt.Println()
	fmt.Println("Equivalent command:")
	fmt.Printf("  sudo krotctl %s\n\n", strings.Join(fullArgs, " "))

	w := newWiz()
	hint("Y = render the config, install the systemd unit and start the service now. n = just print the command above and exit without changing anything.")
	if !w.yesNo("Apply now?", true) {
		fmt.Println("Not applied. Run the command above when ready.")
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("applying needs root — re-run with: sudo krotctl %s", strings.Join(fullArgs, " "))
	}
	return apply()
}
