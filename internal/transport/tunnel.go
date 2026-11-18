package transport

import (
	"errors"
	"fmt"
	"log"
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
// A server Tunnel is alive while it has ≥1 channel: losing channels degrades
// bandwidth, the last channel leaving tears it down and fires onEmpty exactly
// once. A client Tunnel is persistent: it survives having no channels while its
// maintainers redial (packets are dropped meanwhile) and dies only on Close.
type Tunnel struct {
	mu       sync.Mutex
	channels map[int]*channel
	// slots maps flow-hash positions to channel indices (-1 = empty). A dead
	// channel leaves its position empty and its replacement takes the first
	// empty one, so losing or replacing a channel moves only the flows that
	// were on it; flows on an empty position borrow a live one meanwhile.
	slots      []int
	live       []int // positions in slots that hold a channel
	pos        map[int]int
	closed     bool
	persistent bool   // client side: stay open with zero channels
	label      string // log prefix for channel up/down; "" = silent
	addr       string // client side: the session's assigned address

	inbound  chan []byte
	dead     chan struct{}
	deadOnce sync.Once
	onEmpty  func() // called once when the tunnel goes dead (server: release addr)

	dropped atomic.Uint64 // outbound packets dropped on a full channel queue
}

func newTunnel(onEmpty func()) *Tunnel {
	return &Tunnel{
		channels: make(map[int]*channel),
		pos:      make(map[int]int),
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
	// A client redialing a channel can reach us before we noticed the old one
	// died (its TCP may still be stuck in retransmits): the new conn replaces
	// it under the same index.
	old := t.channels[idx]
	t.channels[idx] = ch
	if old == nil {
		t.place(idx)
	}
	t.mu.Unlock()
	if old != nil {
		old.requestStop()
		old.c.Close()
		if t.label != "" {
			log.Printf("%s: channel %d replaced by a new connection", t.label, idx)
		}
	}
	go t.readLoop(idx, ch, done)
	go t.writeLoop(idx, ch)
	go t.healthLoop(idx, ch)
	return done
}

// place puts idx into the first empty flow-hash position. Caller holds mu.
func (t *Tunnel) place(idx int) {
	p := -1
	for i, v := range t.slots {
		if v < 0 {
			p = i
			break
		}
	}
	if p < 0 {
		p = len(t.slots)
		t.slots = append(t.slots, idx)
	} else {
		t.slots[p] = idx
	}
	t.pos[idx] = p
	t.rebuildLive()
}

// rebuildLive recomputes the filled positions. Caller holds mu.
func (t *Tunnel) rebuildLive() {
	t.live = t.live[:0]
	for i, v := range t.slots {
		if v >= 0 {
			t.live = append(t.live, i)
		}
	}
}

// healthLoop replaces a channel whose TCP connection is stuck retransmitting:
// on paths where individual flows stall while fresh ones pass, waiting for
// TCPUserTimeout would hold every flow pinned to it for 10 s.
func (t *Tunnel) healthLoop(idx int, ch *channel) {
	tick := time.NewTicker(healthInterval)
	defer tick.Stop()
	for {
		select {
		case <-ch.stop:
			return
		case <-tick.C:
			if b := rtoBackoff(ch.c.tcp); b >= stuckBackoff {
				t.removeChannel(idx, ch, fmt.Errorf("stuck: %d retransmission timeouts in a row", b))
				return
			}
		}
	}
}

func (t *Tunnel) readLoop(idx int, ch *channel, done chan struct{}) {
	defer close(done)
	for {
		p, err := ch.c.ReadPacket()
		if err != nil {
			t.removeChannel(idx, ch, err)
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
				t.removeChannel(idx, ch, err)
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

// removeChannel detaches ch if it is still the channel at idx (a replaced or
// already-removed channel is a no-op), stops it, and — on a non-persistent
// tunnel — tears the tunnel down when it was the last one.
func (t *Tunnel) removeChannel(idx int, ch *channel, cause error) {
	t.mu.Lock()
	if t.channels[idx] != ch {
		t.mu.Unlock()
		return
	}
	delete(t.channels, idx)
	if p, ok := t.pos[idx]; ok {
		t.slots[p] = -1
		delete(t.pos, idx)
		t.rebuildLive()
	}
	live := len(t.channels)
	closed := t.closed
	t.mu.Unlock()

	ch.requestStop()
	ch.c.Close()
	if t.label != "" && !closed {
		log.Printf("%s: channel %d down: %v (%d live)", t.label, idx, cause, live)
	}
	if live == 0 && !t.persistent {
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
// inner TCP retransmits it. With no channel attached the packet is dropped too
// on a persistent tunnel that is redialing; it errors only once the tunnel is
// dead. The caller must not modify p afterwards — the queue holds it until the
// writer sends it.
func (t *Tunnel) WritePacket(p []byte) error {
	h := flowHash(p)
	t.mu.Lock()
	n := len(t.live)
	if n == 0 {
		closed := t.closed || !t.persistent
		t.mu.Unlock()
		if closed {
			return errTunnelClosed
		}
		t.dropped.Add(1)
		return nil
	}
	idx := t.slots[h%uint32(len(t.slots))]
	if idx < 0 {
		idx = t.slots[t.live[h%uint32(n)]]
	}
	ch := t.channels[idx]
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
	idxs := make([]int, 0, len(t.channels))
	cs := make([]*channel, 0, len(t.channels))
	for idx, ch := range t.channels {
		idxs = append(idxs, idx)
		cs = append(cs, ch)
	}
	closed := t.closed || !t.persistent
	t.mu.Unlock()
	if len(cs) == 0 {
		if closed {
			return errTunnelClosed
		}
		return nil // persistent tunnel between channels: maintainers redial
	}
	for i, ch := range cs {
		if err := ch.c.WriteKeepalive(); err != nil {
			t.removeChannel(idxs[i], ch, err)
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

// isClosed reports whether the tunnel has been torn down.
func (t *Tunnel) isClosed() bool {
	select {
	case <-t.dead:
		return true
	default:
		return false
	}
}

// sleep waits d, returning false early if the tunnel dies meanwhile.
func (t *Tunnel) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-t.dead:
		return false
	}
}

// Close flushes queued packets (bounded by closeFlushTimeout), then tears down
// all channels and the tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	t.closed = true // from here on addChannel refuses new conns
	chans := make([]*channel, 0, len(t.channels))
	for _, ch := range t.channels {
		chans = append(chans, ch)
	}
	t.channels = make(map[int]*channel)
	t.slots, t.live, t.pos = nil, nil, make(map[int]int)
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
