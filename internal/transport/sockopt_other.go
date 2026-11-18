//go:build !linux

package transport

import (
	"net"
	"time"
)

// setUserTimeout is a no-op where TCP_USER_TIMEOUT is unavailable; the read
// deadline still catches dead channels, just more slowly.
func setUserTimeout(net.Conn, time.Duration) {}

// rtoBackoff is unknown off Linux; the health check then never fires.
func rtoBackoff(*net.TCPConn) int { return 0 }
