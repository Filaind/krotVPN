// Package frame implements the Krot record layer that runs on top of the
// camouflage transport. Each record is an AEAD-sealed blob carrying one inner
// IP packet plus randomized padding.
//
// Record plaintext (what gets sealed):
//
//	+--------+--------+----------------+---------------+
//	| type:1 | plen:2 | payload:plen   | padding:rest  |
//	+--------+--------+----------------+---------------+
//
// The padding defeats traffic analysis: the first records of a connection are
// padded up to near-MTU sizes so the burst of an inner (user) TLS handshake —
// the "TLS-in-TLS" fingerprint DPI relies on to spot proxied TLS — is masked.
// Later records get light padding to blur packet sizes cheaply.
//
// One sealed record maps to exactly one transport message (a WebSocket binary
// frame), so no length prefix is needed here; the transport delimits records.
package frame

import (
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"

	"github.com/krot-vpn/krot/internal/crypto"
)

const (
	// TypeData carries a tunneled IP packet.
	TypeData byte = 1
	// TypePad is a pure-padding keepalive/cover record (no payload).
	TypePad byte = 2

	headerLen = 3 // type(1) + plen(2)

	// MaxPayload bounds a single record's payload.
	MaxPayload = 9000
)

var (
	errShort = errors.New("krot/frame: record shorter than header")
	errLen   = errors.New("krot/frame: payload length exceeds record")
	errBig   = errors.New("krot/frame: payload exceeds MaxPayload")
)

// PadPolicy configures the anti-traffic-analysis padding.
type PadPolicy struct {
	BurstRecords int // number of opening records padded aggressively
	BurstMin     int // min target record size during the burst
	BurstMax     int // max target record size during the burst
	SteadyMax    int // max random padding per record afterwards
}

// DefaultPad is tuned for an MTU near 1380.
var DefaultPad = PadPolicy{BurstRecords: 12, BurstMin: 900, BurstMax: 1380, SteadyMax: 128}

// Sealer encrypts outgoing records. Not safe for concurrent use; callers must
// serialize (the transport holds a write mutex).
type Sealer struct {
	aead  *crypto.AEADStream
	pad   PadPolicy
	count int
}

// Opener decrypts incoming records.
type Opener struct {
	aead *crypto.AEADStream
}

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte, pad PadPolicy) (*Sealer, error) {
	a, err := crypto.NewAEADStream(key)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a, pad: pad}, nil
}

// NewOpener builds an Opener from a 32-byte key.
func NewOpener(key []byte) (*Opener, error) {
	a, err := crypto.NewAEADStream(key)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a}, nil
}

// padFor returns how many padding bytes to append given the current payload.
func (s *Sealer) padFor(payloadLen int) int {
	used := headerLen + payloadLen
	if s.count < s.pad.BurstRecords {
		target := s.pad.BurstMin
		if span := s.pad.BurstMax - s.pad.BurstMin; span > 0 {
			target += mrand.IntN(span)
		}
		if target > used {
			return target - used
		}
		return 0
	}
	if s.pad.SteadyMax > 0 {
		return mrand.IntN(s.pad.SteadyMax)
	}
	return 0
}

// Seal builds and encrypts one record, returning the ciphertext to put on the
// wire as a single transport message.
func (s *Sealer) Seal(typ byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, errBig
	}
	pad := s.padFor(len(payload))
	plain := make([]byte, headerLen+len(payload)+pad)
	plain[0] = typ
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(payload)))
	copy(plain[3:], payload)
	if pad > 0 {
		crypto.Random(plain[headerLen+len(payload):])
	}
	s.count++
	return s.aead.Seal(nil, plain)
}

// Open decrypts one record and returns its type and payload (a fresh copy is
// not made; callers using the payload past the next Open must copy it).
func (o *Opener) Open(ciphertext []byte) (typ byte, payload []byte, err error) {
	plain, err := o.aead.Open(nil, ciphertext)
	if err != nil {
		return 0, nil, err
	}
	if len(plain) < headerLen {
		return 0, nil, errShort
	}
	n := int(binary.BigEndian.Uint16(plain[1:3]))
	if n > len(plain)-headerLen {
		return 0, nil, errLen
	}
	return plain[0], plain[headerLen : headerLen+n], nil
}
