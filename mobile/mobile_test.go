package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) OnMessage(from, nick, channel, text string, sent int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, fmt.Sprintf("%s|%s|%s", nick, channel, text))
}

func (r *recorder) has(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if m == s {
			return true
		}
	}
	return false
}

// fakeRadio is the platform side of a link: SendFrame delivers into the
// other end's Link, as a BLE write or notification would.
type fakeRadio struct {
	mu     sync.Mutex
	other  *Link
	closed bool
}

func (f *fakeRadio) SendFrame(frame []byte) error {
	f.mu.Lock()
	o, closed := f.other, f.closed
	f.mu.Unlock()
	if closed || o == nil {
		return errors.New("disconnected")
	}
	o.Receive(frame)
	return nil
}

func (f *fakeRadio) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func connect(t *testing.T, a, b *Node, mtu int) {
	t.Helper()
	ra, rb := &fakeRadio{}, &fakeRadio{}
	la, err := a.LinkUp("b", mtu, ra)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := b.LinkUp("a", mtu, rb)
	if err != nil {
		t.Fatal(err)
	}
	ra.mu.Lock()
	ra.other = lb
	ra.mu.Unlock()
	rb.mu.Lock()
	rb.other = la
	rb.mu.Unlock()
}

func newNode(t *testing.T, nick string) (*Node, *recorder) {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	n, err := NewNode(id, nick, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Stop)
	return n, r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func peers(t *testing.T, n *Node) []peerJSON {
	var ps []peerJSON
	if err := json.Unmarshal([]byte(n.PeersJSON()), &ps); err != nil {
		t.Fatal(err)
	}
	return ps
}

// TestThreePhones is the Phase 6 milestone over fake radios: three phones in
// a line, A and C out of range, exchange encrypted messages through B.
func TestThreePhones(t *testing.T) {
	a, ra := newNode(t, "alice")
	b, rb := newNode(t, "bob")
	c, rc := newNode(t, "carol")
	connect(t, a, b, 182) // a typical negotiated BLE MTU of 185, less the ATT header
	connect(t, b, c, 182)
	waitFor(t, "peers", func() bool { return len(peers(t, a)) == 2 && len(peers(t, c)) == 2 })

	if err := a.SendDirect(c.Fingerprint(), "meet at the north gate"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "direct message", func() bool { return rc.has("alice||meet at the north gate") })
	if err := c.SendDirect(a.Fingerprint(), "on my way"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reply", func() bool { return ra.has("carol||on my way") })
	a.SendChannel("#general", "hello everyone")
	waitFor(t, "broadcast", func() bool { return rb.has("alice|#general|hello everyone") && rc.has("alice|#general|hello everyone") })
	if rb.has("alice||meet at the north gate") || rb.has("carol||on my way") {
		t.Fatal("relay received a direct message")
	}
	var stats struct{ Relayed int }
	json.Unmarshal([]byte(b.StatsJSON()), &stats)
	if stats.Relayed == 0 {
		t.Fatal("b relayed nothing")
	}
}

func TestLinkLifecycle(t *testing.T) {
	a, _ := newNode(t, "alice")
	if _, err := a.LinkUp("x", 182, nil); err == nil {
		t.Fatal("nil handler accepted")
	}
	// An MTU below the mesh minimum is refused by Go, which disconnects it.
	r := &fakeRadio{}
	if _, err := a.LinkUp("tiny", 10, r); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tiny link closed", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.closed
	})
	// A link the platform reports down stops accepting frames.
	k, _ := a.LinkUp("gone", 182, &fakeRadio{})
	k.Down()
	if err := k.WriteFrame([]byte{3}); err == nil {
		t.Fatal("wrote to a downed link")
	}
	k.Receive([]byte{3}) // must not block or panic
	if err := a.Start(); err == nil {
		t.Fatal("started twice")
	}
}

func TestIdentityHelpers(t *testing.T) {
	id, _ := NewIdentity()
	fp, err := Fingerprint(id)
	if err != nil || len(fp) != 64 {
		t.Fatalf("%q %v", fp, err)
	}
	if _, err := Fingerprint([]byte("short")); err == nil {
		t.Fatal("bad identity accepted")
	}
	if _, err := NewNode([]byte("short"), "x", &recorder{}); err == nil {
		t.Fatal("node from a bad identity")
	}
	if CheckNickname("alice") != nil || CheckNickname("") == nil {
		t.Fatal("nickname check")
	}
	n, _ := NewNode(id, "alice", &recorder{})
	if n.Fingerprint() != fp || n.PeersJSON() != "[]" {
		t.Fatal("fresh node")
	}
	n.Start()
	n.Wipe()
	if n.SendChannel("#general", "after wipe") == nil || n.SendDirect(fp, "x") == nil {
		t.Fatal("sent with wiped keys")
	}
}

func TestShouldConnect(t *testing.T) {
	a, b := NewInstance(), NewInstance()
	if len(a) != InstanceSize || ShouldConnect(a, b) == ShouldConnect(b, a) {
		t.Fatal("exactly one side must connect")
	}
	if ShouldConnect(a, a) || ShouldConnect(a, []byte{1}) || ShouldConnect(nil, b) {
		t.Fatal("bad instances")
	}
}
