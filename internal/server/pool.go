package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// ipPool hands out tunnel addresses from the TUN subnet, skipping the network,
// broadcast, and gateway addresses.
type ipPool struct {
	mu     sync.Mutex
	prefix int
	free   []uint32
	used   map[uint32]bool
}

// newIPPool builds a pool from a CIDR like "10.8.0.1/24". The host part of the
// CIDR is the gateway and is excluded.
func newIPPool(cidr string) (*ipPool, error) {
	gwIP, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("bad tun_cidr %q: %w", cidr, err)
	}
	gw4 := gwIP.To4()
	if gw4 == nil {
		return nil, fmt.Errorf("tun_cidr must be IPv4")
	}
	prefix, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("tun_cidr must be IPv4")
	}
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	gw := binary.BigEndian.Uint32(gw4)
	size := uint32(1) << uint(32-prefix)

	p := &ipPool{prefix: prefix, used: make(map[uint32]bool)}
	for off := uint32(1); off < size-1; off++ {
		addr := base + off
		if addr == gw {
			continue
		}
		p.free = append(p.free, addr)
	}
	if len(p.free) == 0 {
		return nil, fmt.Errorf("tun_cidr %q has no usable host addresses", cidr)
	}
	return p, nil
}

// alloc reserves an address, returning it as "a.b.c.d/prefix", its uint32 form,
// and a release closure. ok=false when the pool is empty.
func (p *ipPool) alloc() (cidr string, ip uint32, release func(), ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		return "", 0, nil, false
	}
	ip = p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	p.used[ip] = true

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	cidr = fmt.Sprintf("%d.%d.%d.%d/%d", b[0], b[1], b[2], b[3], p.prefix)

	var once sync.Once
	release = func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.used[ip] {
				delete(p.used, ip)
				p.free = append(p.free, ip)
			}
		})
	}
	return cidr, ip, release, true
}
