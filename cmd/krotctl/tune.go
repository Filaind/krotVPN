package main

import (
	"fmt"
	"os"
)

const (
	tcpTuneSysctlPath = "/etc/sysctl.d/90-krot-tcp.conf"
	tcpTuneModulePath = "/etc/modules-load.d/krot-bbr.conf"
)

// tcpTuneSysctl switches the host to BBR with fq pacing and raises the TCP
// buffer ceilings. Without it a fresh Ubuntu runs cubic with 208 KB socket
// buffer limits: on a lossy RU→EU path a single channel's cwnd collapses to a
// few segments, the server's dispatch blocks on the slow socket, the TUN queue
// overflows and the inner TCP flows see constant loss — measured 0.75 MB/s
// through the tunnel vs 35–43 MB/s on the same path with these settings.
const tcpTuneSysctl = `# krot: BBR + fq pacing and larger TCP buffers for the tunnel channels
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
`

// applyTCPTuning installs and applies tcpTuneSysctl. Best effort: a kernel
// without BBR keeps working on its default congestion control, so failures
// are reported as warnings, not errors. Must run before the daemon starts —
// congestion control is fixed per socket at connect/accept time.
func applyTCPTuning() {
	_ = sh("modprobe", "tcp_bbr")
	if err := os.WriteFile(tcpTuneModulePath, []byte("tcp_bbr\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warn: write %s: %v\n", tcpTuneModulePath, err)
	}
	if err := os.WriteFile(tcpTuneSysctlPath, []byte(tcpTuneSysctl), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warn: write %s: %v\n", tcpTuneSysctlPath, err)
		return
	}
	if err := sh("sysctl", "-p", tcpTuneSysctlPath); err != nil {
		fmt.Fprintf(os.Stderr, "warn: apply TCP tuning (BBR may be unavailable): %v\n", err)
		return
	}
	fmt.Printf("applied TCP tuning (BBR, fq, buffers): %s\n", tcpTuneSysctlPath)
}

// removeTCPTuning deletes the tuning files. The running kernel keeps the
// values until reboot; nothing else on the host depends on them.
func removeTCPTuning() {
	removeFile(tcpTuneSysctlPath)
	removeFile(tcpTuneModulePath)
}
