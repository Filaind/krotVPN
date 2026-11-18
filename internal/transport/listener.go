package transport

import "net"

// WrapListener applies the channel socket options (TCP_USER_TIMEOUT) to every
// accepted connection, so the server drops a stuck channel as fast as the
// client does.
func WrapListener(ln net.Listener) net.Listener { return userTimeoutListener{ln} }

type userTimeoutListener struct{ net.Listener }

func (l userTimeoutListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		setUserTimeout(c, TCPUserTimeout)
	}
	return c, err
}
