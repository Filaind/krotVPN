package transport

import (
	"encoding/binary"

	"github.com/krot-vpn/krot/internal/crypto"
)

// authToken proves PSK knowledge and binds the client ephemeral key, a
// timestamp, the server's static identity, and the bonding session id. Binding
// the static key stops a captured token from being replayed against a different
// server; the timestamp plus the server's replay filter stop same-server
// replay; binding the session id means every channel of a bonded tunnel is
// independently authenticated and a probe cannot graft a channel onto someone
// else's session without the PSK.
func authToken(psk []byte, ephPub [32]byte, ts int64, serverStatic [32]byte, sid []byte) []byte {
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ts))
	return crypto.HMAC(psk, ephPub[:], t[:], serverStatic[:], sid)
}

// combineDH concatenates two X25519 shared secrets. The first pair is the
// ephemeral-ephemeral exchange (forward secrecy); the second mixes the server
// static key (so the client knows it reached the real server and a probe
// cannot derive the keys). Both peers compute the same two secrets in the same
// order via the symmetry of X25519.
func combineDH(priv1, pub1, priv2, pub2 [32]byte) ([]byte, error) {
	ss1, err := crypto.DH(priv1, pub1)
	if err != nil {
		return nil, err
	}
	ss2, err := crypto.DH(priv2, pub2)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 64)
	out = append(out, ss1[:]...)
	out = append(out, ss2[:]...)
	return out, nil
}

// channelSalt is the HKDF salt for one bonded channel. It binds both ephemeral
// public keys, the session id, and the channel index, so each channel (and each
// direction, via DeriveSessionKeys) derives a unique key even though channels
// share a session id. This keeps every channel's AEAD nonce space independent —
// required because ordering is only guaranteed within a single channel.
func channelSalt(clientEph, serverEph [32]byte, sid []byte, chanIdx int) []byte {
	salt := make([]byte, 0, 64+len(sid)+4)
	salt = append(salt, clientEph[:]...)
	salt = append(salt, serverEph[:]...)
	salt = append(salt, sid...)
	var ci [4]byte
	binary.BigEndian.PutUint32(ci[:], uint32(chanIdx))
	salt = append(salt, ci[:]...)
	return salt
}
