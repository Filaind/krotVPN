package crypto

import (
	"testing"
	"time"
)

func TestReplayFilterRejectsRepeat(t *testing.T) {
	f := NewReplayFilter(2 * time.Minute)
	tok := []byte("token-A")
	if !f.Check(tok) {
		t.Fatal("first sighting must be accepted")
	}
	if f.Check(tok) {
		t.Fatal("replay of the same token must be rejected")
	}
	if !f.Check([]byte("token-B")) {
		t.Fatal("a different token must be accepted")
	}
}

// TestReplayFilterWindowHoldsUnderBurst is the property the ring-buffer version
// failed: a token must stay remembered for its whole window no matter how many
// other tokens pass through in between.
func TestReplayFilterWindowHoldsUnderBurst(t *testing.T) {
	f := NewReplayFilter(2 * time.Minute)
	victim := []byte("victim")
	if !f.Check(victim) {
		t.Fatal("victim first sighting must be accepted")
	}
	for i := 0; i < 100000; i++ {
		f.Check([]byte{byte(i), byte(i >> 8), byte(i >> 16), 0xAA})
	}
	if f.Check(victim) {
		t.Fatal("victim replay accepted after a burst — window not held")
	}
}

func TestReplayFilterEvictsAfterTTL(t *testing.T) {
	f := NewReplayFilter(1 * time.Second)
	tok := []byte("ephemeral")
	if !f.Check(tok) {
		t.Fatal("first sighting must be accepted")
	}
	if f.Check(tok) {
		t.Fatal("replay within TTL must be rejected")
	}
	time.Sleep(1100 * time.Millisecond)
	if !f.Check(tok) {
		t.Fatal("token must be accepted again once its TTL has elapsed")
	}
}
