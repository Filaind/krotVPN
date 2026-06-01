// Command krot-probe is a connectivity checker. It dials a Krot server
// using a client config, then sends a real DNS query to 1.1.1.1 *through the
// tunnel* and waits for the reply — proving the full path works (auth, key
// exchange, framing, server-side NAT to the internet, and return routing)
// without needing a TUN device on this machine.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/krot-vpn/krot/internal/config"
	"github.com/krot-vpn/krot/internal/transport"
)

func main() {
	cfgPath := flag.String("config", "probe.json", "path to client config JSON")
	flag.Parse()

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	psk, _ := config.DecodePSK(cfg.PSK)
	pub, _ := config.DecodeKey32(cfg.ServerPub)

	addr := net.JoinHostPort(cfg.ServerIP, fmt.Sprint(cfg.ServerPort))
	fmt.Printf("[*] dialing %s (sni=%s)...\n", addr, cfg.SNI)
	conn, assign, err := transport.Dial(transport.ClientConfig{
		ServerAddr:   addr,
		SNI:          cfg.SNI,
		Path:         cfg.Path,
		PSK:          psk,
		ServerStatic: pub,
		Insecure:     cfg.Insecure,
		PinSHA256:    cfg.PinSHA256,
		Channels:     1, // probe is a simple single-channel reachability check
	})
	if err != nil {
		log.Fatalf("[FAIL] dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[OK] tunnel established. assigned addr=%s gw=%s dns=%s\n", assign.Addr, assign.Gw, assign.DNS)

	srcIP := net.ParseIP(hostOf(assign.Addr)).To4()
	if srcIP == nil {
		log.Fatalf("[FAIL] bad assigned addr %q", assign.Addr)
	}
	dstIP := net.IPv4(1, 1, 1, 1).To4()

	query := buildDNSQuery(srcIP, dstIP, "example.com")
	fmt.Printf("[*] sending DNS A query for example.com -> 1.1.1.1 through the tunnel...\n")
	if err := conn.WritePacket(query); err != nil {
		log.Fatalf("[FAIL] write: %v", err)
	}

	got := make(chan []byte, 1)
	go func() {
		for {
			p, err := conn.ReadPacket()
			if err != nil {
				return
			}
			if len(p) >= 20 && p[9] == 17 && net.IP(p[12:16]).Equal(dstIP) {
				got <- p
				return
			}
		}
	}()

	select {
	case p := <-got:
		ans := parseDNSAnswers(p)
		fmt.Printf("[OK] got %d-byte reply from 1.1.1.1\n", len(p))
		if len(ans) > 0 {
			fmt.Printf("[OK] resolved example.com -> %v\n", ans)
		}
		fmt.Println("\n>>> SUCCESS: the server is routing real internet traffic through the tunnel.")
	case <-time.After(8 * time.Second):
		fmt.Println("[FAIL] no reply within 8s (handshake worked, but egress/NAT may be off)")
		os.Exit(1)
	}
}

func hostOf(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

// buildDNSQuery crafts an IPv4+UDP+DNS A query. The UDP checksum is left 0,
// which is legal over IPv4; the IPv4 header checksum is computed.
func buildDNSQuery(src, dst net.IP, name string) []byte {
	dns := buildDNSMessage(name)
	udpLen := 8 + len(dns)
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)
	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // id
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // don't fragment
	pkt[8] = 64                                  // TTL
	pkt[9] = 17                                  // UDP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 40000) // src port
	binary.BigEndian.PutUint16(pkt[22:24], 53)    // dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	// checksum at [26:28] stays 0
	copy(pkt[28:], dns)
	return pkt
}

func buildDNSMessage(name string) []byte {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0xABCD) // id
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	b = append(b, hdr...)
	// qname
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	b = append(b, 0x00)       // root
	b = append(b, 0x00, 0x01) // type A
	b = append(b, 0x00, 0x01) // class IN
	return b
}

// parseDNSAnswers returns any A records found in the reply (best-effort).
func parseDNSAnswers(ip []byte) []net.IP {
	if len(ip) < 28 {
		return nil
	}
	dns := ip[28:]
	if len(dns) < 12 {
		return nil
	}
	anc := int(binary.BigEndian.Uint16(dns[6:8]))
	// skip question section
	off := 12
	for off < len(dns) && dns[off] != 0 {
		off += int(dns[off]) + 1
	}
	off += 1 + 4 // null + qtype + qclass
	var out []net.IP
	for i := 0; i < anc && off+12 <= len(dns); i++ {
		off += 2 // name pointer
		typ := binary.BigEndian.Uint16(dns[off : off+2])
		off += 8 // type+class+ttl
		rdlen := int(binary.BigEndian.Uint16(dns[off : off+2]))
		off += 2
		if off+rdlen > len(dns) {
			break
		}
		if typ == 1 && rdlen == 4 {
			out = append(out, net.IP(append([]byte(nil), dns[off:off+4]...)))
		}
		off += rdlen
	}
	return out
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
