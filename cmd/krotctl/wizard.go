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
	sni := w.ask("TLS server name (SNI / self-signed CN)", "en.wikipedia.org")
	listen := w.ask("Listen address", ":443")
	decoy := w.ask("Decoy URL for probes (blank = built-in page)", "https://en.wikipedia.org")
	tunCIDR := w.ask("Tunnel subnet (gateway addr/mask)", "10.8.0.1/24")
	dns := w.ask("DNS handed to clients", "1.1.1.1")
	mtu := w.ask("Tunnel MTU", "1320")

	args := []string{
		"-sni", sni, "-listen", listen, "-decoy", decoy,
		"-tun-cidr", tunCIDR, "-dns", dns, "-mtu", mtu,
	}

	if w.yesNo("Use a real TLS cert (Let's Encrypt) instead of self-signed?", false) {
		cert := w.askRequired("  cert chain PEM path")
		key := w.askRequired("  private key PEM path")
		args = append(args, "-cert", cert, "-key", key)
	} else {
		args = append(args, "-self-signed")
	}

	if !w.yesNo("Generate fresh credentials (PSK + server key)?", true) {
		args = append(args, "-psk", w.askRequired("  existing PSK (base64)"),
			"-priv", w.askRequired("  existing server private key (base64)"))
	}
	if _, err := os.Stat(serverCfgPath); err == nil {
		if w.yesNo(fmt.Sprintf("%s exists — overwrite?", serverCfgPath), false) {
			args = append(args, "-force")
		}
	}

	return wizApply("server up", func() error { return serverUp(args) }, append([]string{"server", "up"}, args...))
}

func wizardClient(w *wiz) error {
	fmt.Println("# Client")
	name := w.ask("Instance name", "default")
	mode := w.choice("Routing mode", []string{"full", "socks", "manual"}, "full")
	server := w.askRequired("Server IP to dial")
	port := w.ask("Server port", "443")
	sni := w.askRequired("TLS server name (SNI)")
	path := w.askRequired("Secret WebSocket path")
	psk := w.askRequired("PSK (base64)")
	pub := w.askRequired("Server public key (base64)")
	channels := w.ask("Bonded channels", "4")
	mtu := w.ask("Tunnel MTU", "1320")
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
		args = append(args, "-socks", w.ask("SOCKS5 listen address", "127.0.0.1:1080"))
	}
	if _, err := os.Stat(clientCfgPath(name)); err == nil {
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
	if !w.yesNo("Apply now?", true) {
		fmt.Println("Not applied. Run the command above when ready.")
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("applying needs root — re-run with: sudo krotctl %s", strings.Join(fullArgs, " "))
	}
	return apply()
}
