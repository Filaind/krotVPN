// Package crypto provides the cryptographic primitives for the Krot protocol:
// X25519 key agreement, HKDF-SHA256 key derivation, ChaCha20-Poly1305 AEAD
// stream encryption, and a replay filter for the authentication handshake.
//
// Design notes:
//   - Each server has a static X25519 identity keypair (WireGuard-style).
//     The server publishes its public key; clients carry it in their config.
//   - Each user additionally shares a pre-shared key (PSK) with the server,
//     analogous to a VLESS UUID. Authentication requires knowledge of the PSK.
//   - Every connection mixes a fresh ephemeral X25519 key, giving forward secrecy.
//   - The inner record layer uses ChaCha20-Poly1305 with monotonic counter
//     nonces. This is safe because the records travel over a reliable, ordered
//     TCP stream (inside the outer TLS camouflage), so the counters on each end
//     stay in lockstep and never repeat under a given key.
package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the size of X25519 keys and the AEAD symmetric keys.
	KeySize = 32
	// NonceSize is the ChaCha20-Poly1305 nonce size.
	NonceSize = chacha20poly1305.NonceSize
	// TagSize is the Poly1305 authentication tag size.
	TagSize = 16
)

// ErrCounterExhausted is returned if a single session encrypts more than 2^64
// records (practically unreachable; a guard against silent nonce reuse).
var ErrCounterExhausted = errors.New("krot/crypto: AEAD counter exhausted")

// Keypair is an X25519 static or ephemeral keypair.
type Keypair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeypair returns a fresh random X25519 keypair.
func GenerateKeypair() (Keypair, error) {
	var kp Keypair
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return kp, err
	}
	// curve25519.X25519 performs RFC 7748 clamping internally.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// PublicFromPrivate recomputes the public key for a stored private key.
func PublicFromPrivate(priv [KeySize]byte) ([KeySize]byte, error) {
	var pub [KeySize]byte
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, err
	}
	copy(pub[:], p)
	return pub, nil
}

// DH computes the X25519 shared secret between priv and peerPub.
func DH(priv, peerPub [KeySize]byte) ([KeySize]byte, error) {
	var out [KeySize]byte
	s, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return out, err
	}
	// All-zero output means a low-order point was supplied: reject it.
	if subtle.ConstantTimeCompare(s, make([]byte, KeySize)) == 1 {
		return out, errors.New("krot/crypto: invalid (low-order) peer public key")
	}
	copy(out[:], s)
	return out, nil
}

// HKDF derives n bytes of keying material from the given secret/salt/info.
func HKDF(secret, salt, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		// Only fails if n exceeds 255*HashLen; we stay well under that.
		panic("krot/crypto: HKDF read failed: " + err.Error())
	}
	return out
}

// SessionKeys holds the directional record-layer keys for one connection.
type SessionKeys struct {
	TxKey []byte // key used to encrypt outbound records
	RxKey []byte // key used to decrypt inbound records
}

const (
	// FROZEN WIRE CONSTANTS — do NOT rename. These HKDF "info" labels are part
	// of the on-wire key-derivation transcript: changing them changes every
	// derived session key and breaks compatibility with already-deployed peers
	// (the live server↔gateway). They keep the historical "mirage" value on
	// purpose even though the project is now named krot. Bump to "krot v2 …"
	// only as a deliberate, coordinated protocol version change.
	infoClientToServer = "mirage v1 c2s"
	infoServerToClient = "mirage v1 s2c"
)

// DeriveSessionKeys turns a shared secret into directional AEAD keys.
// Both peers must pass the same salt (the concatenated handshake nonces).
// isClient selects which derived key is used for sending vs receiving so that
// the two ends agree (client Tx == server Rx and vice versa).
func DeriveSessionKeys(shared, salt []byte, isClient bool) SessionKeys {
	c2s := HKDF(shared, salt, []byte(infoClientToServer), KeySize)
	s2c := HKDF(shared, salt, []byte(infoServerToClient), KeySize)
	if isClient {
		return SessionKeys{TxKey: c2s, RxKey: s2c}
	}
	return SessionKeys{TxKey: s2c, RxKey: c2s}
}

// AEADStream is a one-directional ChaCha20-Poly1305 stream with counter nonces.
// It is NOT safe for concurrent use; protect each direction with its own stream.
type AEADStream struct {
	aead    cipher.AEAD
	counter uint64
	nonce   [NonceSize]byte
}

// NewAEADStream creates a stream for a 32-byte key.
func NewAEADStream(key []byte) (*AEADStream, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &AEADStream{aead: a}, nil
}

func (s *AEADStream) advance() error {
	if s.counter == ^uint64(0) {
		return ErrCounterExhausted
	}
	// 12-byte nonce: 4 zero bytes || 64-bit big-endian counter.
	binary.BigEndian.PutUint64(s.nonce[4:], s.counter)
	s.counter++
	return nil
}

// Overhead is the per-record ciphertext expansion (tag bytes).
func (s *AEADStream) Overhead() int { return s.aead.Overhead() }

// Seal encrypts plaintext, appending the ciphertext+tag to dst.
func (s *AEADStream) Seal(dst, plaintext []byte) ([]byte, error) {
	if err := s.advance(); err != nil {
		return nil, err
	}
	return s.aead.Seal(dst, s.nonce[:], plaintext, nil), nil
}

// Open decrypts ciphertext (which includes the tag), appending plaintext to dst.
func (s *AEADStream) Open(dst, ciphertext []byte) ([]byte, error) {
	if err := s.advance(); err != nil {
		return nil, err
	}
	return s.aead.Open(dst, s.nonce[:], ciphertext, nil)
}

// HMAC computes HMAC-SHA256(key, parts...) — used for handshake authentication.
func HMAC(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

// ConstantTimeEqual reports whether a and b are equal without timing leaks.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Random fills b with cryptographically secure random bytes.
func Random(b []byte) {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("krot/crypto: system RNG failure: " + err.Error())
	}
}

// ReplayFilter rejects authentication tokens seen before, for at least the
// freshness window. Eviction is by AGE, not by a fixed-size ring: a token is
// remembered until its TTL expires, so the "no replay within the window"
// guarantee holds regardless of connection rate. (The previous ring-buffer
// version could evict a token before its freshness window closed under a burst
// of >~68 conn/s, briefly reopening the replay hole.) Safe for concurrent use.
//
// Note: the filter is per-process. A multi-instance / load-balanced deployment
// would need a shared store (e.g. Redis) to keep the guarantee across nodes;
// for a single VPS this in-memory filter is sufficient.
type ReplayFilter struct {
	mu     sync.Mutex
	seen   map[string]int64 // token -> unix expiry
	ttl    int64            // seconds a token is remembered
	lastGC int64
}

// NewReplayFilter creates a filter that remembers each token for ttl. ttl
// should be at least the full acceptance span of a token (2× the freshness
// window). A non-positive ttl defaults to 5 minutes.
func NewReplayFilter(ttl time.Duration) *ReplayFilter {
	secs := int64(ttl / time.Second)
	if secs <= 0 {
		secs = 300
	}
	return &ReplayFilter{
		seen: make(map[string]int64),
		ttl:  secs,
	}
}

// Check returns true if the token is fresh (not seen within the TTL) and
// records it. A false return means a replay was detected.
func (f *ReplayFilter) Check(token []byte) bool {
	now := time.Now().Unix()
	key := string(token)
	f.mu.Lock()
	defer f.mu.Unlock()

	// Opportunistic sweep of expired entries, at most once per TTL, so memory
	// stays bounded by (rate × ttl) rather than growing without limit.
	if now-f.lastGC > f.ttl {
		for k, exp := range f.seen {
			if exp <= now {
				delete(f.seen, k)
			}
		}
		f.lastGC = now
	}

	if exp, ok := f.seen[key]; ok && exp > now {
		return false
	}
	f.seen[key] = now + f.ttl
	return true
}
