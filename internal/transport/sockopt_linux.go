package transport

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// setUserTimeout sets TCP_USER_TIMEOUT on a TCP connection (best effort).
func setUserTimeout(c net.Conn, d time.Duration) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	})
}

// rtoBackoff returns the connection's current RTO backoff count — how many
// times in a row the head segment has been retransmitted on timeout (it resets
// as soon as the peer ACKs progress). 0 if unknown.
func rtoBackoff(c *net.TCPConn) int {
	if c == nil {
		return 0
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return 0
	}
	b := 0
	_ = rc.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			b = int(info.Backoff)
		}
	})
	return b
}
