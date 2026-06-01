// Command krot-tlstest isolates the TLS layer: it performs a uTLS Chrome
// handshake to host:port and, on success, sends a plain HTTP GET and prints the
// status line. This separates "TLS/uTLS broken" from "WebSocket/auth broken".
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: krot-tlstest host:port sni")
		os.Exit(2)
	}
	addr, sni := os.Args[1], os.Args[2]
	alpn := []string{"h2", "http/1.1"}
	if len(os.Args) > 3 {
		alpn = strings.Split(os.Args[3], ",")
	}

	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Println("TCP FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("offering ALPN=%v\n", alpn)
	u := utls.UClient(raw, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		MinVersion:         utls.VersionTLS13,
	}, utls.HelloChrome_Auto)

	_ = u.SetDeadline(time.Now().Add(10 * time.Second))
	if err := u.Handshake(); err != nil {
		fmt.Println("HANDSHAKE FAIL:", err)
		os.Exit(1)
	}
	st := u.ConnectionState()
	fmt.Printf("TLS OK  version=0x%x cipher=0x%x alpn=%q\n", st.Version, st.CipherSuite, st.NegotiatedProtocol)

	fmt.Fprintf(u, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", sni)
	br := bufio.NewReader(u)
	line, err := br.ReadString('\n')
	if err != nil {
		fmt.Println("HTTP READ FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("HTTP STATUS:", strings.TrimSpace(line))
}
