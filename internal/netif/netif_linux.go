//go:build linux

// Package netif performs the OS-level network plumbing: bringing up the TUN
// interface, rewriting the client's routing table, and installing server NAT.
// It shells out to iproute2 / iptables, mirroring what an admin would type.
package netif

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func runOut(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// IfUp assigns `cidr` to the interface, sets `mtu`, and brings it up.
func IfUp(name, cidr string, mtu int) error {
	if err := run("ip", "addr", "add", cidr, "dev", name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu)); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", name, "up")
}

// ---- client routing ---------------------------------------------------------

// RouteState records the changes made so they can be reverted on exit.
type RouteState struct {
	serverIP string
	gw       string
	dev      string
	tun      string
	dnsBak   string
}

// routeTo returns the gateway and interface the kernel uses to reach ip.
func routeTo(ip string) (gw, dev string, err error) {
	out, err := runOut("ip", "route", "get", ip)
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("cannot parse route to %s: %q", ip, out)
	}
	return gw, dev, nil
}

// SetupClientRoutes pins a host route to the server via the existing gateway
// (so tunnel packets don't loop) and sends the default route through the TUN
// using the two-/1 trick, which outranks 0.0.0.0/0 without deleting it. When
// dns != "" /etc/resolv.conf is repointed (with a backup).
func SetupClientRoutes(serverIP, tunName, dns string) (*RouteState, error) {
	gw, dev, err := routeTo(serverIP)
	if err != nil {
		return nil, err
	}
	rs := &RouteState{serverIP: serverIP, gw: gw, dev: dev, tun: tunName}

	if gw != "" {
		err = run("ip", "route", "add", serverIP+"/32", "via", gw, "dev", dev)
	} else {
		err = run("ip", "route", "add", serverIP+"/32", "dev", dev)
	}
	if err != nil {
		return nil, err
	}

	if err := run("ip", "route", "add", "0.0.0.0/1", "dev", tunName); err != nil {
		rs.Teardown()
		return nil, err
	}
	if err := run("ip", "route", "add", "128.0.0.0/1", "dev", tunName); err != nil {
		rs.Teardown()
		return nil, err
	}

	if dns != "" {
		if err := rs.setDNS(dns); err != nil {
			rs.Teardown()
			return nil, err
		}
	}
	return rs, nil
}

func (rs *RouteState) setDNS(dns string) error {
	const resolv = "/etc/resolv.conf"
	const bak = "/etc/resolv.conf.krot.bak"
	if cur, err := os.ReadFile(resolv); err == nil {
		if err := os.WriteFile(bak, cur, 0o644); err != nil {
			return err
		}
		rs.dnsBak = bak
	}
	return os.WriteFile(resolv, []byte(fmt.Sprintf("# managed by krot\nnameserver %s\n", dns)), 0o644)
}

// Teardown reverts all routing/DNS changes. Safe to call more than once.
func (rs *RouteState) Teardown() {
	_ = run("ip", "route", "del", "0.0.0.0/1", "dev", rs.tun)
	_ = run("ip", "route", "del", "128.0.0.0/1", "dev", rs.tun)
	if rs.gw != "" {
		_ = run("ip", "route", "del", rs.serverIP+"/32", "via", rs.gw, "dev", rs.dev)
	} else {
		_ = run("ip", "route", "del", rs.serverIP+"/32", "dev", rs.dev)
	}
	if rs.dnsBak != "" {
		if data, err := os.ReadFile(rs.dnsBak); err == nil {
			_ = os.WriteFile("/etc/resolv.conf", data, 0o644)
		}
		_ = os.Remove(rs.dnsBak)
		rs.dnsBak = ""
	}
}

// ---- source-based policy routing (SOCKS chaining mode) ----------------------

// SrcRouteState records the policy-routing rule/route added so SOCKS egress
// (bound to the TUN source IP) is forced out the TUN device.
type SrcRouteState struct {
	srcIP string
	tun   string
	table string
	added bool
}

// SetupSourceRoute makes packets whose source is srcIP (the TUN address) leave
// via the TUN device, using a dedicated routing table. The Krot SOCKS server
// binds its outbound sockets to srcIP, so the kernel sends them through the
// tunnel — no fwmark, no per-app config. Returns a state for teardown.
func SetupSourceRoute(srcIP, tunName, table string) (*SrcRouteState, error) {
	if table == "" {
		table = "100"
	}
	rs := &SrcRouteState{srcIP: srcIP, tun: tunName, table: table}
	// Loose reverse-path filtering so replies on the TUN are accepted.
	_ = run("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2")
	_ = run("sysctl", "-w", "net.ipv4.conf."+tunName+".rp_filter=2")

	// table: default route out the TUN, sourced from srcIP. Use `replace` (not
	// `add`) so a leftover route from a crashed prior instance is overwritten
	// rather than causing a "File exists" failure on restart.
	if err := run("ip", "route", "replace", "default", "dev", tunName, "src", srcIP, "table", table); err != nil {
		return nil, fmt.Errorf("set table route: %w", err)
	}
	// rule: traffic FROM srcIP uses that table. Delete any stale copy first so
	// we don't stack duplicate rules across restarts.
	_ = run("ip", "rule", "del", "from", srcIP, "lookup", table)
	if err := run("ip", "rule", "add", "from", srcIP, "lookup", table); err != nil {
		_ = run("ip", "route", "flush", "table", table)
		return nil, fmt.Errorf("add ip rule: %w", err)
	}
	rs.added = true
	return rs, nil
}

// Teardown removes the policy-routing rule and table route. Safe to call twice.
func (rs *SrcRouteState) Teardown() {
	if rs == nil || !rs.added {
		return
	}
	_ = run("ip", "rule", "del", "from", rs.srcIP, "lookup", rs.table)
	_ = run("ip", "route", "flush", "table", rs.table)
	rs.added = false
}

// ---- server NAT -------------------------------------------------------------

// NATState records the iptables rules installed.
type NATState struct {
	rules [][]string
}

func defaultWAN() (string, error) {
	out, err := runOut("ip", "route", "show", "default")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route found")
}

// SetupServerNAT enables IPv4 forwarding and installs MASQUERADE + FORWARD
// rules so tunnel clients reach the internet via wanIface (auto-detected when
// empty).
func SetupServerNAT(tunName, tunCIDR, wanIface string) (*NATState, error) {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}
	_, ipnet, err := net.ParseCIDR(tunCIDR)
	if err != nil {
		return nil, fmt.Errorf("bad tun cidr %q: %w", tunCIDR, err)
	}
	subnet := ipnet.String()
	if wanIface == "" {
		if wanIface, err = defaultWAN(); err != nil {
			return nil, err
		}
	}
	st := &NATState{}
	rules := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", wanIface, "-j", "MASQUERADE"},
		{"-A", "FORWARD", "-i", tunName, "-o", wanIface, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-i", wanIface, "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, r := range rules {
		if err := run(append([]string{"iptables"}, r...)...); err != nil {
			st.Teardown()
			return nil, err
		}
		st.rules = append(st.rules, r)
	}
	return st, nil
}

// Teardown removes the installed iptables rules.
func (st *NATState) Teardown() {
	for _, r := range st.rules {
		del := make([]string, len(r))
		copy(del, r)
		for i, a := range del {
			if a == "-A" {
				del[i] = "-D"
			}
		}
		_ = run(append([]string{"iptables"}, del...)...)
	}
	st.rules = nil
}
