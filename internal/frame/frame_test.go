package frame

import (
	"bytes"
	"testing"

	"github.com/krot-vpn/krot/internal/crypto"
)

// TestAppendSealedInterop checks that records built by AppendSealed open with
// the regular Opener (what older peers run) and vice versa, across the padding
// burst and steady state, and that the transport header callback sees the
// exact ciphertext length.
func TestAppendSealedInterop(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	crypto.Random(key)

	newS, _ := NewSealer(key, DefaultPad)
	oldS, _ := NewSealer(key, DefaultPad)
	o1, _ := NewOpener(key)
	o2, _ := NewOpener(key)

	for i := 0; i < 40; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, i*37)

		prefix := []byte("hdr:")
		var ctLen int
		buf, err := newS.AppendSealed(append([]byte(nil), prefix...), TypeData, payload, func(dst []byte, n int) []byte {
			ctLen = n
			return append(dst, '|')
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(buf, []byte("hdr:|")) {
			t.Fatalf("record %d: header/prefix lost", i)
		}
		ct := buf[len("hdr:|"):]
		if len(ct) != ctLen {
			t.Fatalf("record %d: header saw ctLen %d, record is %d", i, ctLen, len(ct))
		}
		typ, got, err := o1.Open(ct)
		if err != nil || typ != TypeData || !bytes.Equal(got, payload) {
			t.Fatalf("record %d: AppendSealed→Open: typ=%d err=%v", i, typ, err)
		}

		old, err := oldS.Seal(TypeData, payload)
		if err != nil {
			t.Fatal(err)
		}
		typ, got, err = o2.OpenInPlace(old)
		if err != nil || typ != TypeData || !bytes.Equal(got, payload) {
			t.Fatalf("record %d: Seal→OpenInPlace: typ=%d err=%v", i, typ, err)
		}
	}
}
