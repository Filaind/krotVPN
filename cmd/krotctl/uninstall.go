package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cmdUninstall tears down everything krotctl installs on a host: it stops and
// disables the server and every client instance (which reverts TUN/NAT/routing
// via each daemon's own Close()), removes the systemd units, deletes the
// /etc/krot config tree, and — unless told otherwise — removes the installed
// binaries. It is deliberately best-effort: a missing piece is reported as a
// skip, not a fatal error, so a partial install still cleans up fully.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	keepBins := fs.Bool("keep-binaries", false, "leave the krot* binaries in place")
	keepCfg := fs.Bool("keep-config", false, "leave /etc/krot (configs + secrets) in place")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (systemd/networking/file removal)")
	}

	clients := discoverClientInstances()

	fmt.Println("This will completely remove krot from this host:")
	fmt.Printf("  • stop + disable the server (%s) and revert its TUN/NAT\n", serverUnit)
	if len(clients) > 0 {
		fmt.Printf("  • stop + disable client instances: %s\n", strings.Join(clients, ", "))
	}
	fmt.Printf("  • remove systemd units (%s, %s)\n", serverUnitPath, clientUnitTemplatePath)
	if !*keepCfg {
		fmt.Printf("  • delete %s (configs + secrets — PSK/keys are lost)\n", krotConfigDir)
	}
	if !*keepBins {
		fmt.Printf("  • delete the krot* binaries from %s\n", installDir())
	}
	fmt.Println()

	if !*yes {
		w := newWiz()
		hint("y = proceed with full removal (irreversible). N = abort and change nothing. Default N is the safe choice.")
		if !w.yesNo("Proceed with full uninstall?", false) {
			fmt.Println("Aborted. Nothing was changed.")
			return nil
		}
	}

	// --- stop + disable services (this reverts networking on daemon exit) ---
	stopDisable(serverUnit)
	for _, name := range clients {
		stopDisable(clientUnit(name))
	}

	// --- remove systemd units ---
	removeFile(serverUnitPath)
	removeFile(clientUnitTemplatePath)
	_ = sh("systemctl", "daemon-reload")
	_ = sh("systemctl", "reset-failed")

	// --- remove configs (holds secrets) ---
	if !*keepCfg {
		if err := os.RemoveAll(krotConfigDir); err != nil {
			fmt.Fprintf(os.Stderr, "warn: remove %s: %v\n", krotConfigDir, err)
		} else {
			fmt.Printf("removed %s\n", krotConfigDir)
		}
	}

	// --- remove binaries ---
	if !*keepBins {
		dir := installDir()
		for _, bin := range []string{"krot-server", "krot-client", "krot-keygen", "krotctl"} {
			removeFile(filepath.Join(dir, bin))
		}
		fmt.Println("\nDone. The krotctl binary you are running may still be on disk;")
		fmt.Println("if it was outside the install dir, remove it manually.")
	} else {
		fmt.Println("\nDone. Binaries left in place (-keep-binaries).")
	}
	return nil
}

// discoverClientInstances returns the instance names of every configured client
// by globbing /etc/krot/client-<name>.json.
func discoverClientInstances() []string {
	matches, _ := filepath.Glob(filepath.Join(krotConfigDir, "client-*.json"))
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		base := filepath.Base(m)
		name := strings.TrimSuffix(strings.TrimPrefix(base, "client-"), ".json")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// installDir is the directory the running krotctl lives in — where its sibling
// binaries were installed. Falls back to /usr/local/bin if it can't be found.
func installDir() string {
	self, err := os.Executable()
	if err != nil {
		return "/usr/local/bin"
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return filepath.Dir(self)
}

// stopDisable stops and disables a unit, reporting but not failing on errors.
func stopDisable(unit string) {
	if err := sh("systemctl", "stop", unit); err != nil {
		fmt.Fprintf(os.Stderr, "warn: stop %s: %v\n", unit, err)
	}
	_ = sh("systemctl", "disable", unit)
	fmt.Printf("stopped + disabled %s\n", unit)
}

// removeFile deletes a path, treating "already gone" as success.
func removeFile(path string) {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Fprintf(os.Stderr, "warn: remove %s: %v\n", path, err)
		return
	}
	fmt.Printf("removed %s\n", path)
}
