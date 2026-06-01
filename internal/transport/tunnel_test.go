package transport

import "testing"

// mkPkt builds a minimal IPv4+TCP/UDP packet with the given addresses/ports.
func mkPkt(proto byte, srcA, dstA [4]byte, srcP, dstP uint16) []byte {
	p := make([]byte, 28)
	p[0] = 0x45 // v4, ihl=5
	p[9] = proto
	copy(p[12:16], srcA[:])
	copy(p[16:20], dstA[:])
	p[20] = byte(srcP >> 8)
	p[21] = byte(srcP)
	p[22] = byte(dstP >> 8)
	p[23] = byte(dstP)
	return p
}

// TestFlowHashStableAndDistinct: same flow → same hash (in-order on one
// channel); different flows generally → different hashes (spread across
// channels). Also: both directions of one connection should map together so the
// pinning is consistent enough for the inner TCP.
func TestFlowHashStableAndDistinct(t *testing.T) {
	a := [4]byte{10, 0, 0, 1}
	b := [4]byte{93, 184, 216, 34}

	f1 := mkPkt(6, a, b, 51000, 443)
	if flowHash(f1) != flowHash(append([]byte(nil), f1...)) {
		t.Fatal("same flow must hash identically")
	}

	// A different destination port = different flow → expect a different bucket
	// most of the time (not a hard guarantee, but FNV makes collisions rare).
	f2 := mkPkt(6, a, b, 51000, 8080)
	collisions := 0
	flows := [][]byte{f1, f2,
		mkPkt(6, a, b, 52000, 443),
		mkPkt(17, a, b, 51000, 53),
		mkPkt(6, a, [4]byte{1, 1, 1, 1}, 51000, 443),
	}
	seen := map[uint32]int{}
	for _, f := range flows {
		seen[flowHash(f)%4]++
	}
	// With 5 distinct flows over 4 buckets we expect spread, not all-in-one.
	for _, c := range seen {
		if c == len(flows) {
			collisions++
		}
	}
	if collisions > 0 {
		t.Fatalf("all flows landed in one bucket — hashing not spreading: %v", seen)
	}
}

// TestFlowHashNonIPv4 returns 0 (single shared channel) without panicking.
func TestFlowHashNonIPv4(t *testing.T) {
	if flowHash([]byte{0x60, 0, 0}) != 0 { // IPv6-ish nibble
		t.Fatal("non-IPv4 should hash to 0")
	}
	if flowHash([]byte{}) != 0 {
		t.Fatal("empty packet should hash to 0")
	}
	if flowHash([]byte{0x45, 0, 0}) != 0 { // too short
		t.Fatal("short packet should hash to 0")
	}
}
