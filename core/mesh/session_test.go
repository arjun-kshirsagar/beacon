package mesh

import (
	"bytes"
	"testing"
	"time"
)

// TestDirectMessageRelayCannotRead is the Phase 2 milestone in miniature:
// A and C are out of range of each other and talk through B, who relays
// every byte but cannot read the messages.
func TestDirectMessageRelayCannotRead(t *testing.T) {
	m := newMesh(t, 185)
	nodes := m.line("p", 3)
	a, b, c := nodes[0], nodes[1], nodes[2]
	a.waitPeers(t, 2)
	c.waitPeers(t, 2)

	secret := "meet at the north gate"
	if err := a.SendDirect(c.Fingerprint(), secret); err != nil {
		t.Fatal(err)
	}
	msg := c.waitFor(t, secret, 5*time.Second)
	if msg.From != a.Fingerprint() || msg.Channel != "" || msg.Nickname != "p0" {
		t.Fatalf("message %+v", msg)
	}
	if err := c.SendDirect(a.Fingerprint(), "on my way"); err != nil {
		t.Fatal(err)
	}
	a.waitFor(t, "on my way", 5*time.Second)

	if b.count(secret) != 0 || b.count("on my way") != 0 {
		t.Fatal("relay was handed a direct message")
	}
	b.Node.mu.Lock()
	defer b.Node.mu.Unlock()
	relayed := 0
	for _, s := range b.store {
		if bytes.Contains(s.raw, []byte(secret)) || bytes.Contains(s.raw, []byte("on my way")) {
			t.Fatal("plaintext crossed the relay")
		}
		if p, _ := ParsePacket(s.raw); p != nil && p.Type == TypeEncrypted {
			relayed++
		}
	}
	if relayed != 2 {
		t.Fatalf("relay carried %d encrypted packets, want 2", relayed)
	}
	if len(b.dm.sessions) != 0 {
		t.Fatal("relay holds a session")
	}
}

func TestDirectMessagesBothWaysAtOnce(t *testing.T) {
	m := newMesh(t, 185)
	nodes := m.line("s", 4)
	a, d := nodes[0], nodes[3]
	a.waitPeers(t, 3)
	d.waitPeers(t, 3)
	// Both start a handshake at the same moment; the crossing is resolved
	// and every message arrives once.
	for i := range 5 {
		a.SendDirect(d.Fingerprint(), "from a "+string(rune('0'+i)))
		d.SendDirect(a.Fingerprint(), "from d "+string(rune('0'+i)))
	}
	for i := range 5 {
		d.waitFor(t, "from a "+string(rune('0'+i)), 5*time.Second)
		a.waitFor(t, "from d "+string(rune('0'+i)), 5*time.Second)
	}
	time.Sleep(100 * time.Millisecond)
	if a.count("from d 0") != 1 || d.count("from a 0") != 1 {
		t.Fatal("duplicate delivery")
	}
}

func TestDirectToUnknownPeer(t *testing.T) {
	m := newMesh(t, 185)
	a := m.add("a")
	if err := a.SendDirect(Fingerprint("00"), "hello"); err != ErrUnknownPeer {
		t.Fatalf("err %v", err)
	}
}

func TestReplayedCiphertext(t *testing.T) {
	m := newMesh(t, 185)
	a, b := m.add("a"), m.add("b")
	m.connect("a", "b")
	a.waitPeers(t, 1)
	a.SendDirect(b.Fingerprint(), "pay alice 5")
	b.waitFor(t, "pay alice 5", 5*time.Second)

	// Take the encrypted packet a sent and replay it from a raw device,
	// first as is (a duplicate), then with a fresh packet ID to dodge the
	// duplicate filter. The packet ID is authenticated, so that fails too.
	a.Node.mu.Lock()
	var orig *Packet
	for _, s := range a.store {
		if p, _ := ParsePacket(s.raw); p != nil && p.Type == TypeEncrypted {
			orig = p
		}
	}
	a.Node.mu.Unlock()
	if orig == nil {
		t.Fatal("no encrypted packet stored")
	}
	evil := m.rawLink("evil", "b")
	writePacket(t, evil, orig)
	fresh := *orig
	fresh.ID = PacketID(randomID())
	writePacket(t, evil, &fresh)
	time.Sleep(200 * time.Millisecond)
	if n := b.count("pay alice 5"); n != 1 {
		t.Fatalf("delivered %d times", n)
	}

	// The replay window refuses a nonce it has seen even if a packet got
	// past the duplicate filter (here, the filter is bypassed directly).
	b.Node.mu.Lock()
	msgs := b.dm.handleEncrypted(b.Node, orig, time.Now())
	b.Node.mu.Unlock()
	if len(msgs) != 0 {
		t.Fatal("replayed nonce accepted")
	}
}

func TestSessionRecoversAfterRestart(t *testing.T) {
	m := newMesh(t, 185)
	a := m.add("a")
	id, _ := NewIdentity()
	b := m.add("b", func(c *Config) { c.Identity = id })
	m.connect("a", "b")
	a.waitPeers(t, 1)
	a.SendDirect(b.Fingerprint(), "first")
	b.waitFor(t, "first", 5*time.Second)

	// b restarts with the same identity but no sessions.
	b.Node.mu.Lock()
	b.dm.init()
	b.Node.mu.Unlock()
	a.SendDirect(b.Fingerprint(), "lost")
	time.Sleep(200 * time.Millisecond) // b answers the undecryptable message with a handshake
	a.SendDirect(b.Fingerprint(), "after restart")
	b.waitFor(t, "after restart", 5*time.Second)
}

func TestPadding(t *testing.T) {
	for _, n := range []int{1, 61, 62, 100, 1000, MaxText} {
		text := string(bytes.Repeat([]byte("x"), n))
		p := padText(text)
		ok := false
		for _, s := range paddedSizes {
			ok = ok || len(p) == s
		}
		if !ok {
			t.Fatalf("text of %d padded to %d", n, len(p))
		}
		if got, err := unpadText(p); err != nil || got != text {
			t.Fatalf("round trip of %d bytes: %v", n, err)
		}
	}
	if len(padText("hi")) != len(padText("a longer message, still short")) {
		t.Fatal("short messages leak their length")
	}
	for _, bad := range [][]byte{nil, {2, 0, 1, 'x'}, {1, 0, 9, 'x'}, {1, 0, 0}} {
		if _, err := unpadText(bad); err == nil {
			t.Fatalf("%x accepted", bad)
		}
	}
}

func TestReplayWindow(t *testing.T) {
	var w window
	accept := func(n uint64) bool {
		if !w.fresh(n) {
			return false
		}
		w.mark(n)
		return true
	}
	for _, tt := range []struct {
		n  uint64
		ok bool
	}{
		{0, true}, {0, false}, {5, true}, {3, true}, {3, false}, {5, false},
		{300, true}, {44, false}, {45, true}, {299, true}, {1000, true}, {744, false}, {745, true},
	} {
		if got := accept(tt.n); got != tt.ok {
			t.Fatalf("nonce %d: accepted=%v, want %v", tt.n, got, tt.ok)
		}
	}
}

func TestIdentityProof(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	if pub, ok := checkProof(a.identityProof(), a.NoiseKey()); !ok || FingerprintOf(pub) != a.Fingerprint() {
		t.Fatal("valid proof refused")
	}
	if _, ok := checkProof(a.identityProof(), b.NoiseKey()); ok {
		t.Fatal("proof accepted for another Noise key")
	}
	restored, err := UnmarshalIdentity(a.Marshal())
	if err != nil || restored.Fingerprint() != a.Fingerprint() || restored.NoiseKey() != a.NoiseKey() {
		t.Fatal("identity did not survive marshaling")
	}
	restored.Wipe()
	if !bytes.Equal(restored.sign, make([]byte, len(restored.sign))) {
		t.Fatal("wipe left key material")
	}
}

func TestSharesAndData(t *testing.T) {
	m := newMesh(t, 185)
	nodes := m.line("f", 3)
	a, b, c := nodes[0], nodes[1], nodes[2]
	c.waitPeers(t, 2)
	a.waitPeers(t, 2)

	ih := [20]byte{1, 2, 3}
	if err := a.SendShare(ih, "holiday.mp4", 50<<20); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../etc", "a/b", ".."} {
		if a.SendShare(ih, bad, 1) == nil {
			t.Fatalf("share named %q accepted", bad)
		}
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for " + what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("share", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.shares) == 1
	})
	c.mu.Lock()
	s := c.shares[0]
	c.mu.Unlock()
	if s.From != a.Fingerprint() || s.Nickname != "f0" || s.InfoHash != ih || s.Name != "holiday.mp4" || s.Size != 50<<20 {
		t.Fatalf("share %+v", s)
	}

	// Data goes, encrypted, to one peer only and never shows up as text.
	if err := c.SendDirectData(a.Fingerprint(), []byte{0x01, 0xff, 0x00}); err != nil {
		t.Fatal(err)
	}
	want := string(c.Fingerprint()) + "|" + string([]byte{0x01, 0xff, 0x00})
	waitFor("data", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.data) == 1 && a.data[0] == want
	})
	time.Sleep(50 * time.Millisecond)
	b.mu.Lock()
	leaked := len(b.data) + len(b.got)
	b.mu.Unlock()
	a.mu.Lock()
	asText := len(a.got)
	a.mu.Unlock()
	if leaked != 0 || asText != 0 {
		t.Fatalf("data delivered elsewhere: relay %d, as text %d", leaked, asText)
	}
	if c.SendDirectData(a.Fingerprint(), nil) == nil || c.SendDirectData(a.Fingerprint(), make([]byte, MaxData+1)) == nil {
		t.Fatal("bad data length accepted")
	}
}

func TestParseShare(t *testing.T) {
	ih := [20]byte{9}
	gotIH, name, size, err := parseShare(sharePayload(ih, "a.iso", 7))
	if err != nil || gotIH != ih || name != "a.iso" || size != 7 {
		t.Fatal("round trip", err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 28), sharePayload(ih, "x", 0), sharePayload(ih, "a\\b", 1),
		append(sharePayload(ih, "x", 1), 0)} {
		if _, _, _, err := parseShare(bad); err == nil {
			t.Errorf("%x accepted", bad)
		}
	}
	if k, body, err := unpadInner(padInner(innerData, []byte{0})); err != nil || k != innerData || len(body) != 1 {
		t.Fatal("data round trip")
	}
	if _, _, err := unpadInner(padInner(innerData, nil)); err == nil {
		t.Fatal("empty data accepted")
	}
	if _, err := unpadText(padInner(innerData, []byte("x"))); err == nil {
		t.Fatal("data read as text")
	}
}
