package transport

import (
	"errors"
	"sync"
)

// errTunnelClosed is returned by Tunnel I/O once no channels remain.
var errTunnelClosed = errors.New("krot: tunnel has no live channels")

// Tunnel is a bonded group of WebSocket channels that together behave like one
// logical link. Outbound packets are striped by FLOW HASH across the live
// channels (each inner connection pinned to one channel, in order); inbound
// packets from all channels are merged into a single stream.
//
// Why this is safe without a resequencing buffer: each channel is an
// independent AEAD stream over its own TCP connection, so ordering is
// guaranteed *within* a channel but not *across* channels. That is fine for a
// layer-3 VPN — IP explicitly permits reordering, and the user's inner TCP
// restores order end to end. Skipping resequencing keeps latency low and the
// code simple. (Channels should have similar RTT so cross-channel reorder
// stays small; in practice they share a path to the same server.)
//
// A Tunnel is alive while it has ≥1 channel. Losing channels degrades
// bandwidth but does not drop the tunnel; the last channel leaving tears it
// down and fires onEmpty exactly once.
type Tunnel struct {
	mu       sync.Mutex
	channels map[int]*Conn
	order    []int // active channel indices, indexed by flow hash
	closed   bool

	inbound  chan []byte
	dead     chan struct{}
	deadOnce sync.Once
	onEmpty  func() // called once when the tunnel goes dead (server: release addr)
}

func newTunnel(onEmpty func()) *Tunnel {
	return &Tunnel{
		channels: make(map[int]*Conn),
		inbound:  make(chan []byte, 1024),
		dead:     make(chan struct{}),
		onEmpty:  onEmpty,
	}
}

// addChannel attaches a channel and starts its read loop. The returned channel
// is closed when this specific channel dies (so a server HTTP handler can block
// for the channel's lifetime). If the tunnel is already dead, the conn is
// closed and a closed done-channel is returned.
func (t *Tunnel) addChannel(idx int, c *Conn) <-chan struct{} {
	done := make(chan struct{})
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.Close()
		close(done)
		return done
	}
	t.channels[idx] = c
	t.order = append(t.order, idx)
	t.mu.Unlock()
	go t.readLoop(idx, c, done)
	return done
}

func (t *Tunnel) readLoop(idx int, c *Conn, done chan struct{}) {
	defer close(done)
	for {
		p, err := c.ReadPacket()
		if err != nil {
			t.removeChannel(idx)
			return
		}
		select {
		case t.inbound <- p:
		case <-t.dead:
			return
		}
	}
}

func (t *Tunnel) removeChannel(idx int) {
	t.mu.Lock()
	c, ok := t.channels[idx]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(t.channels, idx)
	out := t.order[:0]
	for _, i := range t.order {
		if i != idx {
			out = append(out, i)
		}
	}
	t.order = out
	empty := len(t.channels) == 0
	t.mu.Unlock()

	c.Close()
	if empty {
		t.markDead()
	}
}

func (t *Tunnel) markDead() {
	t.deadOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		close(t.dead)
		if t.onEmpty != nil {
			t.onEmpty()
		}
	})
}

// channelCount reports how many channels are currently attached.
func (t *Tunnel) channelCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.channels)
}

// WritePacket sends one IP packet on the channel chosen by its flow hash, so
// every inner flow (one TCP/UDP connection) is pinned to a single channel and
// stays in order — the receiver's inner TCP never sees cross-channel reordering
// (which would look like loss and shrink its congestion window). Different flows
// hash to different channels, so aggregate bandwidth across many flows is
// preserved. This is the layer3+4 hashing policy used by Linux bonding / ECMP.
//
// On a channel write error it drops that channel and retries on the next one
// (the inner TCP retransmits the lost packet anyway).
func (t *Tunnel) WritePacket(p []byte) error {
	h := flowHash(p)
	for tries := 0; tries < 4; tries++ {
		t.mu.Lock()
		n := len(t.order)
		if n == 0 {
			t.mu.Unlock()
			return errTunnelClosed
		}
		idx := t.order[(h+uint32(tries))%uint32(n)]
		c := t.channels[idx]
		t.mu.Unlock()

		if err := c.WritePacket(p); err != nil {
			t.removeChannel(idx)
			continue
		}
		return nil
	}
	return errTunnelClosed
}

// flowHash returns a stable hash of an IPv4 packet's flow identity (FNV-1a over
// src/dst address, protocol, and L4 ports), so all packets of one connection
// map to the same channel. Non-IPv4 or too-short packets hash to 0 (they all
// share one channel, which is fine — they are rare control packets).
func flowHash(p []byte) uint32 {
	const (
		off  = 2166136261
		prim = 16777619
	)
	h := uint32(off)
	mix := func(b byte) { h ^= uint32(b); h *= prim }

	if len(p) < 20 || p[0]>>4 != 4 {
		return 0
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return 0
	}
	proto := p[9]
	for _, b := range p[12:20] { // src+dst IPv4 addresses
		mix(b)
	}
	mix(proto)
	// Ports for TCP(6)/UDP(17)/SCTP(132), only on the first (unfragmented) piece.
	fragOffset := (uint16(p[6]&0x1f) << 8) | uint16(p[7])
	if fragOffset == 0 && (proto == 6 || proto == 17 || proto == 132) && len(p) >= ihl+4 {
		mix(p[ihl])   // src port hi
		mix(p[ihl+1]) // src port lo
		mix(p[ihl+2]) // dst port hi
		mix(p[ihl+3]) // dst port lo
	}
	return h
}

// WriteKeepalive sends a keepalive on every live channel (each TCP needs its
// own to stay off the idle/NAT timeout and to refresh its read deadline).
func (t *Tunnel) WriteKeepalive() error {
	t.mu.Lock()
	idxs := append([]int(nil), t.order...)
	cs := make([]*Conn, len(idxs))
	for i, idx := range idxs {
		cs[i] = t.channels[idx]
	}
	t.mu.Unlock()
	if len(cs) == 0 {
		return errTunnelClosed
	}
	for i, c := range cs {
		if err := c.WriteKeepalive(); err != nil {
			t.removeChannel(idxs[i])
		}
	}
	return nil
}

// ReadPacket returns the next merged inbound packet, or an error once the
// tunnel is dead and its buffer is drained.
func (t *Tunnel) ReadPacket() ([]byte, error) {
	select {
	case p := <-t.inbound:
		return p, nil
	case <-t.dead:
		select {
		case p := <-t.inbound:
			return p, nil
		default:
			return nil, errTunnelClosed
		}
	}
}

// Close tears down all channels and the tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	chans := make([]*Conn, 0, len(t.channels))
	for _, c := range t.channels {
		chans = append(chans, c)
	}
	t.channels = make(map[int]*Conn)
	t.order = nil
	t.mu.Unlock()

	for _, c := range chans {
		c.Close()
	}
	t.markDead()
	return nil
}
