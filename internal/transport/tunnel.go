package transport

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// errTunnelClosed is returned by Tunnel I/O once no channels remain.
var errTunnelClosed = errors.New("krot: tunnel has no live channels")

const (
	// sendQueueLen is each channel's outbound queue, in packets (~1.7 MB of
	// full-size packets). WritePacket never blocks: when a channel's queue is
	// full the packet is dropped, like a router's tail drop, and the inner TCP
	// backs off. Blocking instead would let one congested channel stall the
	// single TUN reader and with it every other channel's flows.
	sendQueueLen = 1024
	// maxBatch caps how many queued packets one write call coalesces.
	maxBatch = 128
	// closeFlushTimeout bounds how long Close waits for queued packets to go out.
	closeFlushTimeout = 2 * time.Second
)

// channel is one bonded WebSocket plus its outbound queue and writer goroutine.
type channel struct {
	c        *Conn
	q        chan []byte
	stop     chan struct{} // closed to ask the writer to flush and exit
	stopOnce sync.Once
	flushed  chan struct{} // closed when the writer has exited
}

func (ch *channel) requestStop() { ch.stopOnce.Do(func() { close(ch.stop) }) }

// Tunnel is a bonded group of WebSocket channels that together behave like one
// logical link. Outbound packets are striped by FLOW HASH across the live
// channels (each inner connection pinned to one channel, in order); inbound
// packets from all channels are merged into a single stream.
//
// Every channel has its own queue and writer goroutine, so channels encrypt and
// write in parallel and a slow channel delays only the flows pinned to it. The
// writer drains whatever is queued and sends it as one batch — one TLS write
// instead of one per packet.
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
	channels map[int]*channel
	order    []int // active channel indices, indexed by flow hash
	closed   bool

	inbound  chan []byte
	dead     chan struct{}
	deadOnce sync.Once
	onEmpty  func() // called once when the tunnel goes dead (server: release addr)

	dropped atomic.Uint64 // outbound packets dropped on a full channel queue
}

func newTunnel(onEmpty func()) *Tunnel {
	return &Tunnel{
		channels: make(map[int]*channel),
		inbound:  make(chan []byte, 4096),
		dead:     make(chan struct{}),
		onEmpty:  onEmpty,
	}
}

// addChannel attaches a channel and starts its read and write loops. The
// returned channel is closed when this specific channel dies (so a server HTTP
// handler can block for the channel's lifetime). If the tunnel is already dead,
// the conn is closed and a closed done-channel is returned.
func (t *Tunnel) addChannel(idx int, c *Conn) <-chan struct{} {
	done := make(chan struct{})
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.Close()
		close(done)
		return done
	}
	ch := &channel{
		c:       c,
		q:       make(chan []byte, sendQueueLen),
		stop:    make(chan struct{}),
		flushed: make(chan struct{}),
	}
	t.channels[idx] = ch
	t.order = append(t.order, idx)
	t.mu.Unlock()
	go t.readLoop(idx, ch, done)
	go t.writeLoop(idx, ch)
	return done
}

func (t *Tunnel) readLoop(idx int, ch *channel, done chan struct{}) {
	defer close(done)
	for {
		p, err := ch.c.ReadPacket()
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

// writeLoop sends a channel's queued packets, coalescing everything already
// waiting into one batch. On stop it flushes what is left and exits.
func (t *Tunnel) writeLoop(idx int, ch *channel) {
	defer close(ch.flushed)
	batch := make([][]byte, 0, maxBatch)
	drain := func() {
		for len(batch) < maxBatch {
			select {
			case p := <-ch.q:
				batch = append(batch, p)
			default:
				return
			}
		}
	}
	for {
		select {
		case p := <-ch.q:
			batch = append(batch[:0], p)
			drain()
			if err := ch.c.writeBatch(batch); err != nil {
				t.removeChannel(idx)
				return
			}
		case <-ch.stop:
			for {
				batch = batch[:0]
				drain()
				if len(batch) == 0 {
					return
				}
				if ch.c.writeBatch(batch) != nil {
					return
				}
			}
		}
	}
}

func (t *Tunnel) removeChannel(idx int) {
	t.mu.Lock()
	ch, ok := t.channels[idx]
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

	ch.requestStop()
	ch.c.Close()
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

// Dropped reports how many outbound packets were dropped on full queues.
func (t *Tunnel) Dropped() uint64 { return t.dropped.Load() }

// WritePacket queues one IP packet on the channel chosen by its flow hash, so
// every inner flow (one TCP/UDP connection) is pinned to a single channel and
// stays in order — the receiver's inner TCP never sees cross-channel reordering
// (which would look like loss and shrink its congestion window). Different flows
// hash to different channels, so aggregate bandwidth across many flows is
// preserved. This is the layer3+4 hashing policy used by Linux bonding / ECMP.
//
// It never blocks: a full queue drops the packet (counted in Dropped) and the
// inner TCP retransmits it. It errors only when no channel is left. The caller
// must not modify p afterwards — the queue holds it until the writer sends it.
func (t *Tunnel) WritePacket(p []byte) error {
	h := flowHash(p)
	t.mu.Lock()
	n := len(t.order)
	if n == 0 {
		t.mu.Unlock()
		return errTunnelClosed
	}
	ch := t.channels[t.order[h%uint32(n)]]
	t.mu.Unlock()

	select {
	case ch.q <- p:
	default:
		t.dropped.Add(1)
	}
	return nil
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
	cs := make([]*channel, len(idxs))
	for i, idx := range idxs {
		cs[i] = t.channels[idx]
	}
	t.mu.Unlock()
	if len(cs) == 0 {
		return errTunnelClosed
	}
	for i, ch := range cs {
		if err := ch.c.WriteKeepalive(); err != nil {
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

// Close flushes queued packets (bounded by closeFlushTimeout), then tears down
// all channels and the tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	chans := make([]*channel, 0, len(t.channels))
	for _, ch := range t.channels {
		chans = append(chans, ch)
	}
	t.channels = make(map[int]*channel)
	t.order = nil
	t.mu.Unlock()

	for _, ch := range chans {
		ch.requestStop()
	}
	timer := time.NewTimer(closeFlushTimeout)
	defer timer.Stop()
wait:
	for _, ch := range chans {
		select {
		case <-ch.flushed:
		case <-timer.C:
			break wait
		}
	}
	for _, ch := range chans {
		ch.c.Close()
	}
	t.markDead()
	return nil
}
