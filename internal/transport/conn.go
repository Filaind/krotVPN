package transport

import (
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
	// writeTimeout bounds a single frame write so a stuck socket cannot wedge a
	// writer goroutine while holding wmu.
	writeTimeout = 15 * time.Second
)

// Conn is one live Krot tunnel: a WebSocket carrying AEAD-sealed, padded
// records. WritePacket/ReadPacket move single IP packets.
//
// Concurrency contract: exactly one reader goroutine calls ReadPacket; any
// number of goroutines may call WritePacket/WriteKeepalive. Sealing and the
// socket write happen together under wmu so that the AEAD nonce-counter order
// is identical to the on-wire order. (If Seal ran outside the lock, two writer
// goroutines could grab nonces N and N+1 but write them N+1, N — the receiver,
// which opens strictly in nonce order, would then fail authentication and the
// tunnel would reset.)
type Conn struct {
	ws   *websocket.Conn
	seal *frame.Sealer
	open *frame.Opener
	wmu  sync.Mutex
}

func newConn(ws *websocket.Conn, sealKey, openKey []byte, pad frame.PadPolicy) (*Conn, error) {
	s, err := frame.NewSealer(sealKey, pad)
	if err != nil {
		return nil, err
	}
	o, err := frame.NewOpener(openKey)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(int64(frame.MaxPayload + 2048))
	return &Conn{ws: ws, seal: s, open: o}, nil
}

// WritePacket seals and sends one IP packet. Seal+write are atomic under wmu.
func (c *Conn) WritePacket(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	ct, err := c.seal.Seal(frame.TypeData, p)
	if err != nil {
		return err
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.ws.WriteMessage(websocket.BinaryMessage, ct)
}

// WriteKeepalive sends a padding-only record (cover traffic + idle keepalive).
func (c *Conn) WriteKeepalive() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	ct, err := c.seal.Seal(frame.TypePad, nil)
	if err != nil {
		return err
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.ws.WriteMessage(websocket.BinaryMessage, ct)
}

// ReadPacket blocks until the next data packet, dropping padding records. A
// read deadline is (re)armed before every frame so a dead peer is detected.
func (c *Conn) ReadPacket() ([]byte, error) {
	for {
		_ = c.ws.SetReadDeadline(time.Now().Add(readTimeout))
		_, ct, err := c.ws.ReadMessage()
		if err != nil {
			return nil, err
		}
		typ, payload, err := c.open.Open(ct)
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
