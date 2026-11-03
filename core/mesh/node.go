package mesh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/noise"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// Limits and timings; see docs/protocol-spec.md.
const (
	maxAge         = 15 * time.Minute // oldest packet accepted
	maxSkew        = 5 * time.Minute  // furthest in the future a packet may claim to be
	storeFor       = 10 * time.Minute // store-and-forward lifetime
	maxStored      = 256
	maxPeers       = 1024
	peerTTL        = 20 * time.Minute // a peer is forgotten this long after its last announce
	maxPending     = 8                // unverified packets held per unknown sender
	maxPendingFrom = 64               // unknown senders with packets held
	pendingFor     = time.Minute
	linkQueue      = 512 // packets queued per link before dropping
	linkRate       = 50  // packets a second accepted from one link
	linkBurst      = 200
	senderRate     = 20 // packets a second accepted from one origin
	senderBurst    = 100
	maxSenders     = 4096
	seenPerGen     = 16384
)

// Config configures a Node. Zero durations pick the defaults.
type Config struct {
	Identity *Identity
	Nickname string
	Links    transport.LinkTransport
	// OnMessage receives channel and direct messages. It is called from the
	// node's goroutines, one message at a time per link, with no locks held.
	OnMessage func(Message)
	Logger    *slog.Logger

	AnnounceEvery time.Duration // default 5 minutes
	RotateEvery   time.Duration // ephemeral ID lifetime; default 15 minutes
	Now           func() time.Time
}

// Message is a channel or direct message delivered to the application.
type Message struct {
	From     Fingerprint
	Nickname string
	Channel  string // empty for a direct message
	Text     string
	Time     time.Time // when the sender wrote it
}

// Peer is a node heard from on the mesh.
type Peer struct {
	Fingerprint Fingerprint
	Nickname    string
	LastSeen    time.Time
}

// Stats counts what a node has done.
type Stats struct {
	Links, Peers, Stored            int
	Delivered, Relayed, Duplicates  uint64
	Dropped, RateLimited, BadSigned uint64
}

// Node is one participant in the mesh: it originates, verifies, delivers and
// relays packets over whatever links the platform gives it.
type Node struct {
	cfg Config
	id  *Identity
	log *slog.Logger

	mu       sync.Mutex
	myID     PeerID
	prevID   PeerID // still accepted for one rotation
	rotated  time.Time
	nickname string
	links    map[*link]bool
	seen     *seen
	peers    map[PeerID]*peerInfo
	pending  map[PeerID][]pendingPacket
	store    []stored
	senders  *limiter[PeerID]
	dm       dmState
	stats    Stats
}

type peerInfo struct {
	fp       Fingerprint
	nickname string
	signKey  ed25519.PublicKey
	noiseKey [noise.KeySize]byte
	lastSeen time.Time
}

type pendingPacket struct {
	p    *Packet
	from *link
	at   time.Time
}

type stored struct {
	raw []byte // TTL already set for the next hop
	at  time.Time
}

type link struct {
	l      transport.Link
	out    chan []byte
	tokens bucket
	done   chan struct{}
}

// New returns a node. Call Run to start it.
func New(cfg Config) (*Node, error) {
	if cfg.Identity == nil || cfg.Links == nil {
		return nil, errors.New("mesh: Identity and Links are required")
	}
	if err := checkNickname(cfg.Nickname); err != nil {
		return nil, err
	}
	if cfg.AnnounceEvery <= 0 {
		cfg.AnnounceEvery = 5 * time.Minute
	}
	if cfg.RotateEvery <= 0 {
		cfg.RotateEvery = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	n := &Node{
		cfg: cfg, id: cfg.Identity, nickname: cfg.Nickname,
		log:     cfg.Logger.With("node", cfg.Identity.Fingerprint().Short()),
		links:   make(map[*link]bool),
		seen:    newSeen(seenPerGen, 1e-6),
		peers:   make(map[PeerID]*peerInfo),
		pending: make(map[PeerID][]pendingPacket),
		senders: newLimiter[PeerID](senderRate, senderBurst, maxSenders),
	}
	n.dm.init()
	n.myID = randomID()
	n.prevID = n.myID
	n.rotated = cfg.Now()
	return n, nil
}

func randomID() (id [IDSize]byte) {
	rand.Read(id[:])
	return id
}

// Fingerprint returns this node's fingerprint.
func (n *Node) Fingerprint() Fingerprint { return n.id.Fingerprint() }

// Run accepts links and keeps the node announced until ctx ends.
func (n *Node) Run(ctx context.Context) error {
	n.mu.Lock()
	n.announceLocked()
	n.mu.Unlock()
	go n.housekeeping(ctx)
	for {
		l, err := n.cfg.Links.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("mesh: accepting links: %w", err)
		}
		n.addLink(ctx, l)
	}
}

func (n *Node) housekeeping(ctx context.Context) {
	tick := time.NewTicker(min(n.cfg.AnnounceEvery, n.cfg.RotateEvery, time.Second) / 2)
	defer tick.Stop()
	lastAnnounce := n.cfg.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := n.cfg.Now()
		n.mu.Lock()
		if now.Sub(n.rotated) >= n.cfg.RotateEvery {
			n.prevID, n.myID, n.rotated = n.myID, randomID(), now
			n.dm.rotated()
			n.announceLocked()
			lastAnnounce = now
		} else if now.Sub(lastAnnounce) >= n.cfg.AnnounceEvery {
			n.announceLocked()
			lastAnnounce = now
		}
		n.expireLocked(now)
		n.dm.tick(n, now)
		n.mu.Unlock()
	}
}

func (n *Node) addLink(ctx context.Context, tl transport.Link) {
	if tl.MTU() < MinMTU {
		n.log.Warn("link MTU too small", "peer", tl.Peer(), "mtu", tl.MTU())
		tl.Close()
		return
	}
	l := &link{l: tl, out: make(chan []byte, linkQueue), done: make(chan struct{})}
	n.mu.Lock()
	n.links[l] = true
	// Store-and-forward: a new neighbour gets everything still worth relaying,
	// oldest first, including our own announce.
	now := n.cfg.Now()
	for _, s := range n.store {
		if now.Sub(s.at) < storeFor {
			n.sendLocked(l, s.raw)
		}
	}
	n.mu.Unlock()
	n.log.Debug("link up", "peer", tl.Peer())

	go n.writeLoop(l)
	go func() {
		n.readLoop(l)
		n.mu.Lock()
		delete(n.links, l)
		n.mu.Unlock()
		close(l.done)
		tl.Close()
		n.log.Debug("link down", "peer", tl.Peer())
	}()
	go func() {
		select {
		case <-ctx.Done():
			tl.Close()
		case <-l.done:
		}
	}()
}

func (n *Node) writeLoop(l *link) {
	for {
		select {
		case raw := <-l.out:
			for _, f := range fragment(raw, l.l.MTU()) {
				if err := l.l.WriteFrame(f); err != nil {
					l.l.Close()
					return
				}
			}
		case <-l.done:
			return
		}
	}
}

func (n *Node) readLoop(l *link) {
	var asm assembler
	for {
		frame, err := l.l.ReadFrame()
		if err != nil {
			return
		}
		raw, err := asm.add(frame)
		if err != nil || raw == nil {
			continue
		}
		n.receive(l, raw)
	}
}

// sendLocked queues raw for l, dropping it if the link is backed up: a slow
// neighbour must not stall the node.
func (n *Node) sendLocked(l *link, raw []byte) {
	select {
	case l.out <- raw:
	default:
		n.stats.Dropped++
	}
}

// receive handles one packet from a link.
func (n *Node) receive(l *link, raw []byte) {
	var deliver []Message
	n.mu.Lock()
	now := n.cfg.Now()
	if !l.tokens.allow(now, linkRate, linkBurst) {
		n.stats.RateLimited++
		n.mu.Unlock()
		return
	}
	p, err := ParsePacket(raw)
	if err != nil {
		n.stats.Dropped++
		n.mu.Unlock()
		return
	}
	deliver = n.handleLocked(p, l, now)
	n.mu.Unlock()
	n.deliver(deliver)
}

func (n *Node) deliver(msgs []Message) {
	for _, m := range msgs {
		if n.cfg.OnMessage != nil {
			n.cfg.OnMessage(m)
		}
	}
}

func dedupKey(p *Packet) []byte {
	return append(p.Sender[:len(p.Sender):len(p.Sender)], p.ID[:]...)
}

func (n *Node) mine(id PeerID) bool { return id == n.myID || id == n.prevID }

func (n *Node) handleLocked(p *Packet, from *link, now time.Time) []Message {
	if p.Time.Before(now.Add(-maxAge)) || p.Time.After(now.Add(maxSkew)) {
		n.stats.Dropped++
		return nil
	}
	if n.seen.check(dedupKey(p)) {
		n.stats.Duplicates++
		return nil
	}
	if n.mine(p.Sender) {
		return nil // our own packet, back by another path
	}
	if !n.senders.allow(p.Sender, now) {
		n.stats.RateLimited++
		return nil
	}
	// A signed packet from a sender we know must verify before we relay it, so
	// forgeries die at the first hop that knows the real key.
	if p.Type.signed() && p.Type != TypeAnnounce {
		if peer := n.peers[p.Sender]; peer != nil && !p.Verify(peer.signKey) {
			n.stats.BadSigned++
			return nil
		}
	}
	if p.Recipient != nil && n.mine(*p.Recipient) {
		return n.dm.handle(n, p, now)
	}
	if p.Type == TypeAnnounce && !n.handleAnnounce(p, now) {
		return nil
	}
	n.relayLocked(p, from, now)
	switch p.Type {
	case TypeAnnounce:
		return n.flushPending(p.Sender, now)
	case TypeChannel:
		return n.handleChannel(p, from, now)
	}
	return nil
}

// relayLocked forwards p to every link but from and stores it for neighbours
// who arrive later.
func (n *Node) relayLocked(p *Packet, from *link, now time.Time) {
	if p.TTL == 0 {
		return
	}
	q := *p
	q.TTL--
	raw := q.Encode()
	n.storeLocked(raw, now)
	for l := range n.links {
		if l != from {
			n.sendLocked(l, raw)
		}
	}
	n.stats.Relayed++
}

func (n *Node) storeLocked(raw []byte, now time.Time) {
	if len(n.store) >= maxStored {
		n.store = append(n.store[:0], n.store[1:]...)
	}
	n.store = append(n.store, stored{raw: raw, at: now})
}

// stampLocked fills in a new packet's header.
func (n *Node) stampLocked(p *Packet) {
	p.TTL = MaxTTL
	p.ID = PacketID(randomID())
	p.Time = n.cfg.Now().Truncate(time.Millisecond)
	p.Sender = n.myID
}

// originateLocked stamps, signs (if its type requires) and sends a new packet.
func (n *Node) originateLocked(p *Packet) {
	n.stampLocked(p)
	n.sendStampedLocked(p)
}

// sendStampedLocked signs (if its type requires) and sends a stamped packet.
func (n *Node) sendStampedLocked(p *Packet) {
	if p.Type.signed() {
		p.Sign(n.id.sign)
	}
	n.seen.check(dedupKey(p))
	raw := p.Encode()
	n.storeLocked(raw, p.Time)
	for l := range n.links {
		n.sendLocked(l, raw)
	}
}

func (n *Node) announceLocked() {
	a := announce{signKey: n.id.SigningKey(), noiseKey: n.id.NoiseKey(), nickname: n.nickname}
	n.originateLocked(&Packet{Type: TypeAnnounce, Payload: a.encode()})
}

// handleAnnounce records a peer, reporting whether the announce was valid and
// should be relayed.
func (n *Node) handleAnnounce(p *Packet, now time.Time) bool {
	a, err := parseAnnounce(p.Payload)
	if err != nil || !p.Verify(a.signKey) {
		n.stats.BadSigned++
		return false
	}
	fp := FingerprintOf(a.signKey)
	if old := n.peers[p.Sender]; old != nil && old.fp != fp && now.Sub(old.lastSeen) < peerTTL {
		// Someone else claims a live ID: keep the first binding.
		n.stats.BadSigned++
		return false
	}
	if len(n.peers) >= maxPeers && n.peers[p.Sender] == nil {
		n.evictPeer()
	}
	n.peers[p.Sender] = &peerInfo{fp: fp, nickname: a.nickname, signKey: a.signKey, noiseKey: a.noiseKey, lastSeen: now}
	return true
}

func (n *Node) evictPeer() {
	var oldest PeerID
	var at time.Time
	for id, p := range n.peers {
		if at.IsZero() || p.lastSeen.Before(at) {
			oldest, at = id, p.lastSeen
		}
	}
	delete(n.peers, oldest)
}

func (n *Node) handleChannel(p *Packet, from *link, now time.Time) []Message {
	peer := n.peers[p.Sender]
	if peer == nil {
		// Its announce may still be on the way; hold the packet briefly.
		q := n.pending[p.Sender]
		if len(q) < maxPending && (q != nil || len(n.pending) < maxPendingFrom) {
			n.pending[p.Sender] = append(q, pendingPacket{p: p, from: from, at: now})
		}
		return nil
	}
	m, err := parseChannelMessage(p.Payload)
	if err != nil {
		n.stats.Dropped++
		return nil
	}
	n.stats.Delivered++
	return []Message{{From: peer.fp, Nickname: peer.nickname, Channel: m.channel, Text: m.text, Time: p.Time}}
}

// flushPending delivers packets that were waiting for sender's announce.
func (n *Node) flushPending(sender PeerID, now time.Time) []Message {
	q := n.pending[sender]
	delete(n.pending, sender)
	var out []Message
	for _, pp := range q {
		if !pp.p.Verify(n.peers[sender].signKey) {
			n.stats.BadSigned++
			continue
		}
		out = append(out, n.handleChannel(pp.p, pp.from, now)...)
	}
	return out
}

func (n *Node) expireLocked(now time.Time) {
	for id, p := range n.peers {
		if now.Sub(p.lastSeen) > peerTTL {
			delete(n.peers, id)
		}
	}
	for id, q := range n.pending {
		if now.Sub(q[0].at) > pendingFor {
			delete(n.pending, id)
		}
	}
	i := 0
	for i < len(n.store) && now.Sub(n.store[i].at) >= storeFor {
		i++
	}
	n.store = append(n.store[:0], n.store[i:]...)
}

// SendChannel broadcasts text to a public channel such as "#general".
func (n *Node) SendChannel(channel, text string) error {
	if err := CheckChannel(channel); err != nil {
		return err
	}
	if err := checkText(text); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.originateLocked(&Packet{Type: TypeChannel, Payload: channelMessage{channel: channel, text: text}.encode()})
	return nil
}

// Peers lists the peers heard from recently, one entry per fingerprint.
func (n *Node) Peers() []Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	byFP := map[Fingerprint]Peer{}
	for _, p := range n.peers {
		if cur, ok := byFP[p.fp]; !ok || p.lastSeen.After(cur.LastSeen) {
			byFP[p.fp] = Peer{Fingerprint: p.fp, Nickname: p.nickname, LastSeen: p.lastSeen}
		}
	}
	out := make([]Peer, 0, len(byFP))
	for _, p := range byFP {
		out = append(out, p)
	}
	return out
}

// Stats returns counters.
func (n *Node) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.stats
	s.Links, s.Peers, s.Stored = len(n.links), len(n.peers), len(n.store)
	return s
}
