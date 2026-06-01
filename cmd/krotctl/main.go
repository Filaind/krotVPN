// Command krotctl is the on-node deployment tool for Krot. Copy the binary
// to a host and run it there; it generates secrets, renders configs, installs
// the systemd unit, and brings the service up — replacing the old pile of
// ad-hoc shell scripts with one tested Go tool.
//
// Usage:
//
//	krotctl keygen [-o dir]                 generate secrets + client template
//	krotctl server up   [flags]             render config, install unit, start
//	krotctl server run  -config <path>      run in foreground (systemd calls this)
//	krotctl server status                   show service / TUN / NAT state
//	krotctl server down                     stop service + revert networking
//	krotctl uninstall [flags]               remove everything krot installed
//
// Most commands need root (TUN, iptables, systemd).
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time via -ldflags "-X main.version=<tag>".
// Defaults to "dev" for local/un-tagged builds.
var version = "dev"

func main() {
	// No arguments → launch the interactive wizard (friendliest default).
	if len(os.Args) < 2 {
		if err := cmdWizard(nil); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	var err error
	switch os.Args[1] {
	case "wizard", "setup", "init":
		err = cmdWizard(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	case "uninstall", "purge", "remove":
		err = cmdUninstall(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("krotctl %s (krot VPN)\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`krotctl — Krot VPN deployment tool (run on the node)

Run with no arguments for an interactive setup wizard.

Commands:
  wizard                   Interactive step-by-step setup (server or client).

  keygen [-o DIR]          Generate PSK + server identity + secret path.
                           Prints credentials and writes a client.json template.

  server up [flags]        Render /etc/krot/server.json, install & start the
                           systemd service (krot-server), set up TUN + NAT.
    -sni HOST              TLS server name / self-signed CN     (default en.wikipedia.org)
    -listen ADDR           bind address                         (default :443)
    -decoy URL             reverse-proxy target for probes      (default "")
    -tun-cidr CIDR         tunnel subnet (gateway addr)         (default 10.8.0.1/24)
    -dns IP                DNS handed to clients                (default 1.1.1.1)
    -mtu N                 tunnel MTU                           (default 1320)
    -self-signed           use a throwaway cert (testing)       (default true)
    -cert FILE -key FILE   real TLS cert+key (Let's Encrypt) instead of self-signed
    -psk B64 -priv B64     reuse existing secrets (else generated)
    -force                 overwrite an existing config

  server run -config PATH  Run the server in the foreground (used by systemd).
  server status            Show service, TUN device, NAT rules, listener.
  server down              Stop the service and revert TUN + NAT.

  client up [flags]        Render /etc/krot/client-<name>.json, install the
                           templated unit, start krot-client@<name>.
    -name N                instance name (several clients per host)  (default default)
    -mode M                full | socks | manual                     (default full)
    -server IP -port N     server to dial                            (port default 443)
    -sni H -path P         TLS name + secret path                    (required)
    -psk B64 -server-pub B64                                          (required)
    -channels N -mtu N -dns IP -insecure
    -socks ADDR            socks mode: SOCKS5 listen   (default 127.0.0.1:1080)
    -socks-table T         socks mode: routing table   (default: derived from name)
    -force                 overwrite an existing instance config

  client run -config PATH  Run a client instance in the foreground (systemd).
  client status [-name N]  Show instance service, TUN, SOCKS, source rule.
  client down  [-name N]   Stop the instance and revert its routing/TUN.

  uninstall [flags]        Completely remove krot: stop + disable the server and
                           all client instances (reverting TUN/NAT/routing),
                           delete systemd units, /etc/krot, and the binaries.
    -yes                   skip the confirmation prompt
    -keep-config           leave /etc/krot (configs + secrets) in place
    -keep-binaries         leave the krot* binaries in place

Examples:
  sudo krotctl server up -sni en.wikipedia.org -decoy https://en.wikipedia.org
  sudo krotctl client up -mode full   -server 46.224.77.233 -sni en.wikipedia.org \
       -path /api/v2/xxx -psk <b64> -server-pub <b64>
  sudo krotctl client up -mode socks  -name xray -server 46.224.77.233 \
       -sni en.wikipedia.org -path /api/v2/xxx -psk <b64> -server-pub <b64> \
       -socks 127.0.0.1:1080
  sudo krotctl client status -name xray
  sudo krotctl uninstall            # full removal (asks for confirmation)
  sudo krotctl uninstall -yes -keep-binaries
`)
}
