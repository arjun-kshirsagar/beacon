package mesh

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// testNode is a node on an in-memory radio that records what it receives.
type testNode struct {
	*Node
	name   string
	mu     sync.Mutex
	got    []Message
	data   []string // "from|data" for each OnData
	shares []Share
	ch     chan Message
}

type testMesh struct {
	t     *testing.T
	radio *transport.Radio
	ctx   context.Context
	nodes map[string]*testNode
}

func newMesh(t *testing.T, mtu int) *testMesh {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &testMesh{t: t, radio: transport.NewRadio(mtu), ctx: ctx, nodes: map[string]*testNode{}}
}

func (m *testMesh) add(name string, mod ...func(*Config)) *testNode {
	m.t.Helper()
	tn := m.create(name, mod...)
	go tn.Run(m.ctx)
	return tn
}

// create adds a node without starting it.
func (m *testMesh) create(name string, mod ...func(*Config)) *testNode {
	m.t.Helper()
	id, err := NewIdentity()
	if err != nil {
		m.t.Fatal(err)
	}
	tn := &testNode{name: name, ch: make(chan Message, 1024)}
	cfg := Config{Identity: id, Nickname: name, Links: m.radio.Node(name), OnMessage: func(msg Message) {
		tn.mu.Lock()
		tn.got = append(tn.got, msg)
		tn.mu.Unlock()
		select {
		case tn.ch <- msg:
		default:
		}
	}}
	cfg.OnData = func(from Fingerprint, data []byte) {
		tn.mu.Lock()
		tn.data = append(tn.data, string(from)+"|"+string(data))
		tn.mu.Unlock()
	}
	cfg.OnShare = func(s Share) {
		tn.mu.Lock()
		tn.shares = append(tn.shares, s)
		tn.mu.Unlock()
	}
	for _, f := range mod {
		f(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		m.t.Fatal(err)
	}
	tn.Node = n
	m.nodes[name] = tn
	return tn
}

func (m *testMesh) connect(a, b string) {
	m.t.Helper()
	if err := m.radio.Connect(a, b); err != nil {
		m.t.Fatal(err)
	}
}

// line adds n nodes named prefix0..prefixN-1 joined in a chain.
func (m *testMesh) line(prefix string, n int) []*testNode {
	var out []*testNode
	for i := range n {
		out = append(out, m.add(fmt.Sprintf("%s%d", prefix, i)))
		if i > 0 {
			m.connect(fmt.Sprintf("%s%d", prefix, i-1), fmt.Sprintf("%s%d", prefix, i))
		}
	}
	return out
}

// waitFor waits until node has received a message matching text.
func (tn *testNode) waitFor(t *testing.T, text string, d time.Duration) Message {
	t.Helper()
	deadline := time.After(d)
	for {
		if m, ok := tn.find(text); ok {
			return m
		}
		select {
		case <-tn.ch:
		case <-deadline:
			t.Fatalf("%s never received %q", tn.name, text)
		}
	}
}

func (tn *testNode) find(text string) (Message, bool) {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	for _, m := range tn.got {
		if m.Text == text {
			return m, true
		}
	}
	return Message{}, false
}

func (tn *testNode) count(text string) int {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	c := 0
	for _, m := range tn.got {
		if m.Text == text {
			c++
		}
	}
	return c
}

// waitPeers waits until node knows want peers.
func (tn *testNode) waitPeers(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(tn.Peers()) < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s knows %d peers, want %d", tn.name, len(tn.Peers()), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestChannelThroughRelay(t *testing.T) {
	m := newMesh(t, 64)
	nodes := m.line("n", 3)
	a, c := nodes[0], nodes[2]
	c.waitPeers(t, 2)
	if err := a.SendChannel("#general", "hello over two hops"); err != nil {
		t.Fatal(err)
	}
	msg := c.waitFor(t, "hello over two hops", 5*time.Second)
	if msg.From != a.Fingerprint() || msg.Nickname != "n0" || msg.Channel != "#general" {
		t.Fatalf("message %+v", msg)
	}
	time.Sleep(50 * time.Millisecond)
	if a.count("hello over two hops") != 0 {
		t.Fatal("sender received its own message")
	}
	if nodes[1].count("hello over two hops") != 1 || c.count("hello over two hops") != 1 {
		t.Fatal("message not delivered exactly once")
	}
}

func TestTTLLimitsHops(t *testing.T) {
	m := newMesh(t, 185)
	nodes := m.line("h", MaxTTL+3)
	nodes[MaxTTL+1].waitPeers(t, MaxTTL+1)
	nodes[0].SendChannel("#general", "how far")
	// The origin sends with TTL 7, so it reaches 8 hops and no further.
	nodes[MaxTTL+1].waitFor(t, "how far", 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if nodes[MaxTTL+2].count("how far") != 0 {
		t.Fatal("packet travelled past its TTL")
	}
}

func TestStoreAndForward(t *testing.T) {
	m := newMesh(t, 185)
	a, b, c := m.add("a"), m.add("b"), m.add("c")
	// a writes while alone; b arrives later and gets it.
	a.SendChannel("#general", "written offline")
	m.connect("a", "b")
	b.waitFor(t, "written offline", 5*time.Second)
	// a leaves; b carries the message to c, who never met a.
	m.radio.Disconnect("a", "b")
	m.connect("b", "c")
	msg := c.waitFor(t, "written offline", 5*time.Second)
	if msg.From != a.Fingerprint() {
		t.Fatal("wrong sender")
	}
}

// rawLink connects a test-controlled "device" to node and returns its end.
func (m *testMesh) rawLink(name, node string) transport.Link {
	m.t.Helper()
	m.connect(name, node)
	l, err := m.radio.Node(name).Accept(m.ctx)
	if err != nil {
		m.t.Fatal(err)
	}
	// Drain what the node sends so it never backs up.
	go func() {
		for {
			if _, err := l.ReadFrame(); err != nil {
				return
			}
		}
	}()
	return l
}

func writePacket(t *testing.T, l transport.Link, p *Packet) {
	t.Helper()
	for _, f := range fragment(p.Encode(), l.MTU()) {
		if err := l.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
}

// forger builds packets for an identity without running a node.
type forger struct {
	id     *Identity
	sender PeerID
}

func newForger(t *testing.T, nick string) *forger {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &forger{id: id, sender: PeerID(randomID())}
}

func (f *forger) packet(typ Type, payload []byte, key ed25519.PrivateKey) *Packet {
	p := &Packet{Type: typ, TTL: MaxTTL, ID: PacketID(randomID()), Time: time.Now().Truncate(time.Millisecond),
		Sender: f.sender, Payload: payload}
	if key != nil {
		p.Sign(key)
	}
	return p
}

func (f *forger) announce(nick string) *Packet {
	a := announce{signKey: f.id.SigningKey(), noiseKey: f.id.NoiseKey(), nickname: nick}
	return f.packet(TypeAnnounce, a.encode(), f.id.sign)
}

func (f *forger) channel(text string, key ed25519.PrivateKey) *Packet {
	return f.packet(TypeChannel, channelMessage{channel: "#general", text: text}.encode(), key)
}

func TestSignaturesAndPending(t *testing.T) {
	m := newMesh(t, 185)
	a, b := m.add("a"), m.add("b")
	m.connect("a", "b")
	evil := m.rawLink("evil", "a")
	f := newForger(t, "mallory")

	// A message before its sender's announce waits, then is delivered.
	writePacket(t, evil, f.channel("early", f.id.sign))
	time.Sleep(50 * time.Millisecond)
	if a.count("early") != 0 {
		t.Fatal("unverified message delivered")
	}
	writePacket(t, evil, f.announce("mallory"))
	a.waitFor(t, "early", 2*time.Second)
	b.waitFor(t, "early", 2*time.Second) // relayed, and verified at b too

	// A message signed by someone else's key under a known sender ID is
	// dropped and not relayed.
	other, _ := NewIdentity()
	writePacket(t, evil, f.channel("forged", other.sign))
	writePacket(t, evil, f.channel("after", f.id.sign))
	a.waitFor(t, "after", 2*time.Second)
	b.waitFor(t, "after", 2*time.Second)
	if a.count("forged") != 0 || b.count("forged") != 0 {
		t.Fatal("forged message delivered")
	}
	if a.Stats().BadSigned == 0 {
		t.Fatal("forgery not counted")
	}

	// Another identity cannot take over a live sender ID.
	hijack := &forger{id: other, sender: f.sender}
	writePacket(t, evil, hijack.announce("mallory2"))
	writePacket(t, evil, hijack.channel("hijacked", other.sign))
	time.Sleep(100 * time.Millisecond)
	if a.count("hijacked") != 0 {
		t.Fatal("sender ID hijacked")
	}
}

func TestDuplicatesAndReplays(t *testing.T) {
	m := newMesh(t, 185)
	a := m.add("a")
	evil := m.rawLink("evil", "a")
	f := newForger(t, "m")
	writePacket(t, evil, f.announce("m"))
	p := f.channel("once", f.id.sign)
	writePacket(t, evil, p)
	writePacket(t, evil, p)
	a.waitFor(t, "once", 2*time.Second)

	// A stale packet, validly signed, is refused.
	old := f.channel("stale", nil)
	old.Time = time.Now().Add(-maxAge - time.Minute).Truncate(time.Millisecond)
	old.Sign(f.id.sign)
	writePacket(t, evil, old)
	writePacket(t, evil, f.channel("fresh", f.id.sign))
	a.waitFor(t, "fresh", 2*time.Second)
	if a.count("once") != 1 || a.count("stale") != 0 {
		t.Fatalf("once delivered %d times, stale %d", a.count("once"), a.count("stale"))
	}
}

func TestLinkFlood(t *testing.T) {
	m := newMesh(t, 185)
	a, b := m.add("a"), m.add("b")
	m.connect("a", "b")
	b.waitPeers(t, 1)
	evil := m.rawLink("evil", "a")
	f := newForger(t, "m")
	writePacket(t, evil, f.announce("m"))
	for i := range 2000 {
		f.sender = PeerID(randomID()) // fresh sender IDs dodge the per-origin limit
		writePacket(t, evil, f.channel(fmt.Sprint("spam ", i), f.id.sign))
	}
	time.Sleep(100 * time.Millisecond)
	if s := a.Stats(); s.RateLimited < 1000 || s.Relayed > linkBurst+200 {
		t.Fatalf("flood not limited: %+v", s)
	}
	// The honest link still works.
	b.SendChannel("#general", "still alive")
	a.waitFor(t, "still alive", 2*time.Second)
}

func TestRotation(t *testing.T) {
	m := newMesh(t, 185)
	fast := func(c *Config) { c.RotateEvery = 300 * time.Millisecond }
	a := m.add("a", fast)
	b := m.add("b")
	m.connect("a", "b")
	b.waitPeers(t, 1)
	a.Node.mu.Lock()
	first := a.myID
	a.Node.mu.Unlock()
	time.Sleep(700 * time.Millisecond)
	a.Node.mu.Lock()
	rotated := a.myID != first
	a.Node.mu.Unlock()
	if !rotated {
		t.Fatal("ID did not rotate")
	}
	a.SendChannel("#general", "after rotation")
	if msg := b.waitFor(t, "after rotation", 2*time.Second); msg.From != a.Fingerprint() {
		t.Fatal("wrong sender after rotation")
	}
	if len(b.Peers()) != 1 {
		t.Fatalf("rotation shows as %d peers", len(b.Peers()))
	}
}

func TestPayloadValidation(t *testing.T) {
	for _, ch := range []string{"#general", "#a", "#lost-and_found9"} {
		if CheckChannel(ch) != nil {
			t.Errorf("%q rejected", ch)
		}
	}
	for _, ch := range []string{"", "#", "general", "#General", "#a b", "#" + string(make([]byte, MaxChannel))} {
		if CheckChannel(ch) == nil {
			t.Errorf("%q accepted", ch)
		}
	}
	for _, nick := range []string{"", "a\x00b", "bad‮nick", string([]byte{0xff})} {
		if CheckNickname(nick) == nil {
			t.Errorf("nickname %q accepted", nick)
		}
	}
	if _, err := parseChannelMessage([]byte{50, '#'}); err == nil {
		t.Error("channel length past the payload accepted")
	}
}

// shortLiveness speeds up keepalives and link timeouts for one test.
func shortLiveness(t *testing.T) {
	ke, lt := keepaliveEvery, linkTimeout
	keepaliveEvery, linkTimeout = 50*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { keepaliveEvery, linkTimeout = ke, lt })
}

func TestLinkLiveness(t *testing.T) {
	shortLiveness(t)
	m := newMesh(t, 185)
	a, b := m.add("a"), m.add("b")
	m.connect("a", "b")
	b.waitPeers(t, 1)

	// A device that links but never sends anything (its app died while the
	// radio stayed up) is dropped after the timeout.
	m.rawLink("dead", "a")
	deadline := time.Now().Add(2 * time.Second)
	for a.Stats().Links != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if a.Stats().Links != 2 {
		t.Fatalf("dead link never came up: %d links", a.Stats().Links)
	}
	for a.Stats().Links != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := a.Stats().Links; n != 1 {
		t.Fatalf("silent link not dropped: %d links", n)
	}

	// Two idle nodes keep their link through many timeouts, thanks to
	// keepalives, and still carry messages.
	time.Sleep(5 * linkTimeout)
	if a.Stats().Links != 1 || b.Stats().Links != 1 {
		t.Fatalf("idle honest link dropped: a %d, b %d", a.Stats().Links, b.Stats().Links)
	}
	a.SendChannel("#general", "still here")
	b.waitFor(t, "still here", 2*time.Second)
}

func TestKeepaliveFrameIsIgnored(t *testing.T) {
	var a assembler
	if p, err := a.add(keepaliveFrame); p != nil || err != nil {
		t.Fatalf("keepalive gave %x, %v", p, err)
	}
	// It never interrupts a packet: the write loop sends it only between
	// packets, and a whole packet still assembles after one.
	frames := fragment([]byte("hello, mesh"), 6)
	var got []byte
	for _, f := range frames {
		got, _ = a.add(f)
	}
	if string(got) != "hello, mesh" {
		t.Fatalf("packet after keepalive: %q", got)
	}
}

// waitStat polls one of node's stats until it reaches want.
func waitStat(t *testing.T, tn *testNode, what string, get func(Stats) int, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for get(tn.Stats()) != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := get(tn.Stats()); got != want {
		t.Fatalf("%s: %d, want %d", tn.name, got, want)
	}
}

func links(s Stats) int { return s.Links }
func peers(s Stats) int { return s.Peers }

func TestDuplicateLinks(t *testing.T) {
	m := newMesh(t, 185)
	a := m.add("a")
	b := newForger(t, "b")
	ann := b.announce("b")

	// b links to a, then links again from a new BLE address, as a phone does
	// when it changes its advertisement: a keeps only the newer link.
	old := m.rawLink("b-old", "a")
	writePacket(t, old, ann)
	waitStat(t, a, "peers", peers, 1)
	waitStat(t, a, "links", links, 1)
	newer := m.rawLink("b-new", "a")
	writePacket(t, newer, ann)
	waitStat(t, a, "duplicates closed", func(s Stats) int { return int(s.DuplicateLinks) }, 1)
	waitStat(t, a, "links after duplicate", links, 1)
	if old.WriteFrame(keepaliveFrame) == nil {
		t.Fatal("the older link is still open")
	}
	if err := newer.WriteFrame(keepaliveFrame); err != nil {
		t.Fatalf("the newer link was closed: %v", err)
	}

	// Anyone can replay b's announce with the full TTL (the TTL is not
	// signed), so within the cooldown a further duplicate is left alone
	// rather than cutting b's link again.
	writePacket(t, m.rawLink("replay", "a"), ann)
	waitStat(t, a, "links after replay", links, 2)
	time.Sleep(100 * time.Millisecond)
	if s := a.Stats(); s.Links != 2 || s.DuplicateLinks != 1 {
		t.Fatalf("replay within cooldown closed a link: %d links, %d closed", s.Links, s.DuplicateLinks)
	}

	// A relayed copy (TTL below the maximum) says nothing about the link.
	c := newForger(t, "c")
	relayed := c.announce("c")
	relayed.TTL = MaxTTL - 1
	writePacket(t, m.rawLink("c-1", "a"), relayed)
	writePacket(t, m.rawLink("c-2", "a"), relayed)
	waitStat(t, a, "links after relayed announces", links, 4)
}

func TestAnnounceOnEveryLink(t *testing.T) {
	m := newMesh(t, 185)
	a := m.add("a")
	waitStat(t, a, "stored", func(s Stats) int { return min(s.Stored, 1) }, 1)
	// Push a's announce out of its store-and-forward buffer.
	for i := range maxStored + 10 {
		if err := a.SendChannel("#general", fmt.Sprintf("filler %d", i)); err != nil {
			t.Fatal(err)
		}
	}

	m.connect("x", "a")
	l, err := m.radio.Node("x").Accept(m.ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan *Packet, 1)
	go func() {
		var asm assembler
		for {
			f, err := l.ReadFrame()
			if err != nil {
				return
			}
			if raw, _ := asm.add(f); raw != nil {
				p, _ := ParsePacket(raw)
				first <- p
				return
			}
		}
	}()
	select {
	case p := <-first:
		if p == nil || p.Type != TypeAnnounce || p.TTL != MaxTTL {
			t.Fatalf("first packet on a new link is %+v, want a's announce with the full TTL", p)
		}
		ann, err := parseAnnounce(p.Payload)
		if err != nil || FingerprintOf(ann.signKey) != a.Fingerprint() {
			t.Fatal("first packet is someone else's announce")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing sent on a new link")
	}
}
