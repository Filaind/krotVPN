package transport

import (
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/krot-vpn/krot/internal/frame"
)

const (
	// readTimeout bounds how long ReadPacket waits for any frame. Both peers
	// send a keepalive every ~20s, so a healthy tunnel refreshes the deadline
	// well within this window; a peer that vanishes without TCP RST/FIN (mobile
	// drop, NAT timeout) makes ReadPacket error out instead of blocking forever,
	// so handleConn returns and frees its pool address. Must be comfortably
	// larger than the keepalive interval to tolerate a couple of missed beats.
	readTimeout = 60 * time.Second
	// writeTimeout bounds a single batch write so a stuck socket cannot wedge a
	// writer goroutine while holding wmu.
	writeTimeout = 15 * time.Second

	// flushBytes is how much framed data a batch accumulates before it is
	// handed to TLS in one Write (which TLS cuts into ≤16 KB records). One
	// Write per batch instead of one per packet is what lets a channel move
	// hundreds of Mbit/s: per-packet writes cost a TLS record + a syscall each.
	flushBytes = 64 << 10
	// wsMaxHeader is the largest WebSocket frame header we emit (2 + 8-byte
	// length + 4-byte mask).
	wsMaxHeader = 14
)

var errMsgTooBig = errors.New("krot: websocket message exceeds read buffer")

// Conn is one live Krot channel: a WebSocket carrying AEAD-sealed, padded
// records, one record per binary message.
//
// Writes bypass gorilla's per-message Write: records are framed here (standard
// RFC 6455 binary frames, masked on the client side as the RFC requires) into
// one buffer and written to the TLS connection in a single call, so the peer's
// gorilla reader — any krot version — parses them as ordinary messages. The
// only other writer on the socket is gorilla's control-frame path (pong/close
// replies), and each of those is a single TLS Write too, so frames never
// interleave mid-frame.
//
// Concurrency contract: exactly one reader goroutine calls ReadPacket; any
// number of goroutines may call the write methods. Sealing and the socket write
// happen together under wmu so that the AEAD nonce-counter order is identical
// to the on-wire order. (If Seal ran outside the lock, two writer goroutines
// could grab nonces N and N+1 but write them N+1, N — the receiver, which opens
// strictly in nonce order, would then fail authentication and the tunnel would
// reset.)
type Conn struct {
	ws       *websocket.Conn
	raw      net.Conn // the TLS connection under ws
	isClient bool     // client→server frames must be masked
	seal     *frame.Sealer
	open     *frame.Opener

	wmu  sync.Mutex
	wbuf []byte

	rbuf []byte // reader-goroutine only
}

func newConn(ws *websocket.Conn, sealKey, openKey []byte, pad frame.PadPolicy, isClient bool) (*Conn, error) {
	s, err := frame.NewSealer(sealKey, pad)
	if err != nil {
		return nil, err
	}
	o, err := frame.NewOpener(openKey)
	if err != nil {
		return nil, err
	}
	maxMsg := frame.MaxPayload + 2048
	ws.SetReadLimit(int64(maxMsg))
	return &Conn{
		ws: ws, raw: ws.UnderlyingConn(), isClient: isClient,
		seal: s, open: o,
		wbuf: make([]byte, 0, flushBytes+frame.MaxPayload+2048+wsMaxHeader),
		rbuf: make([]byte, maxMsg),
	}, nil
}

// wsHeader appends an RFC 6455 FIN+binary frame header for a payload of n
// bytes. On the client the mask bit is set and the 4-byte key follows; the
// caller masks the payload with maskKey afterwards.
func wsHeader(dst []byte, n int, isClient bool, maskKey uint32) []byte {
	var m byte
	if isClient {
		m = 0x80
	}
	dst = append(dst, 0x82) // FIN | opcode binary
	switch {
	case n < 126:
		dst = append(dst, m|byte(n))
	case n <= 0xffff:
		dst = append(dst, m|126, byte(n>>8), byte(n))
	default:
		dst = append(dst, m|127)
		dst = binary.BigEndian.AppendUint64(dst, uint64(n))
	}
	if isClient {
		dst = binary.BigEndian.AppendUint32(dst, maskKey)
	}
	return dst
}

// maskBytes XORs b with the 4-byte WebSocket mask key (big-endian on the
// wire), eight bytes at a time.
func maskBytes(b []byte, key uint32) {
	var k [4]byte
	binary.BigEndian.PutUint32(k[:], key)
	k8 := binary.LittleEndian.Uint64([]byte{k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]})
	i := 0
	for ; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], binary.LittleEndian.Uint64(b[i:])^k8)
	}
	for ; i < len(b); i++ {
		b[i] ^= k[i&3]
	}
}

// appendRecord seals one record and appends it to c.wbuf as a WebSocket frame.
// Caller holds wmu.
func (c *Conn) appendRecord(typ byte, p []byte) error {
	var key uint32
	if c.isClient {
		key = mrand.Uint32()
	}
	var body int
	out, err := c.seal.AppendSealed(c.wbuf, typ, p, func(dst []byte, ctLen int) []byte {
		dst = wsHeader(dst, ctLen, c.isClient, key)
		body = len(dst)
		return dst
	})
	if err != nil {
		return err
	}
	if c.isClient {
		maskBytes(out[body:], key)
	}
	c.wbuf = out
	return nil
}

// flush writes the accumulated frames in one call. Caller holds wmu.
func (c *Conn) flush() error {
	if len(c.wbuf) == 0 {
		return nil
	}
	_ = c.raw.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.raw.Write(c.wbuf)
	c.wbuf = c.wbuf[:0]
	return err
}

// writeBatch seals and sends packets as consecutive records, flushing to the
// socket every flushBytes and once at the end.
func (c *Conn) writeBatch(pkts [][]byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for _, p := range pkts {
		if err := c.appendRecord(frame.TypeData, p); err != nil {
			c.wbuf = c.wbuf[:0]
			return err
		}
		if len(c.wbuf) >= flushBytes {
			if err := c.flush(); err != nil {
				return err
			}
		}
	}
	return c.flush()
}

// WritePacket seals and sends one IP packet synchronously.
func (c *Conn) WritePacket(p []byte) error {
	return c.writeBatch([][]byte{p})
}

// WriteKeepalive sends a padding-only record (cover traffic + idle keepalive).
func (c *Conn) WriteKeepalive() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.appendRecord(frame.TypePad, nil); err != nil {
		c.wbuf = c.wbuf[:0]
		return err
	}
	return c.flush()
}

// readMessage reads the next WebSocket data message into c.rbuf.
func (c *Conn) readMessage() ([]byte, error) {
	_, r, err := c.ws.NextReader()
	if err != nil {
		return nil, err
	}
	n := 0
	for {
		if n == len(c.rbuf) {
			// gorilla's read limit should make this unreachable.
			return nil, errMsgTooBig
		}
		k, err := r.Read(c.rbuf[n:])
		n += k
		if err == io.EOF {
			return c.rbuf[:n], nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// ReadPacket blocks until the next data packet, dropping padding records. A
// read deadline is (re)armed before every frame so a dead peer is detected.
// The returned slice is freshly allocated and owned by the caller.
func (c *Conn) ReadPacket() ([]byte, error) {
	for {
		_ = c.ws.SetReadDeadline(time.Now().Add(readTimeout))
		ct, err := c.readMessage()
		if err != nil {
			return nil, err
		}
		typ, payload, err := c.open.OpenInPlace(ct)
		if err != nil {
			return nil, err
		}
		if typ == frame.TypePad {
			continue
		}
		out := make([]byte, len(payload))
		copy(out, payload)
		return out, nil
	}
}

// Close tears down the underlying WebSocket. Safe to call from any goroutine;
// it unblocks a ReadPacket/WritePacket in progress.
func (c *Conn) Close() error { return c.ws.Close() }
