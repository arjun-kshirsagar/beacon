package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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
	linkQueue      = 512           // packets queued per link before dropping
	linkRate       = 50            // packets a second accepted from one link
	linkBurst      = 2 * maxStored // room for a neighbour's whole store-and-forward flush
	senderRate     = 20            // packets a second accepted from one origin
	senderBurst    = 100
	maxSenders     = 4096
	seenPerGen     = 16384
	recentPerGen   = 4096 // packets whose best TTL is remembered, per generation
)

// Link liveness: an idle link carries a keepalive frame every keepaliveEvery,
// and a link silent for linkTimeout is closed, so a neighbour whose app died
// while its radio stayed up does not linger. Variables so tests can shorten them.
var (
	keepaliveEvery = 5 * time.Second
	linkTimeout    = 15 * time.Second
)

// dupLinkCooldown limits how often a duplicate link to one neighbour is
// closed. The TTL is not signed, so a device on another link can replay a
// neighbour's announce with the full TTL and pass for it; the cooldown bounds
// how often that can cut the real link.
const dupLinkCooldown = time.Minute

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
	DuplicateLinks                  uint64 // links closed for leading to a neighbour already linked
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
	best     *bestTTL
	peers    map[PeerID]*peerInfo
	pending  map[PeerID][]pendingPacket
	store    []stored
	senders  *limiter[PeerID]
	dm       dmState
	stats    Stats

	keepalive, linkTimeout time.Duration // copied from the package defaults

	announceRaw []byte                    // our latest announce, sent on every new link
	dupClosed   map[Fingerprint]time.Time // when a duplicate link to each neighbour was last closed
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
	l        transport.Link
	out      chan []byte
	tokens   bucket
	done     chan struct{}
	lastRecv atomic.Int64 // unix nanoseconds of the last frame received

	created   time.Time
	neighbour Fingerprint // who is at the other end, once known; guarded by Node.mu
}

// New returns a node. Call Run to start it.
func New(cfg Config) (*Node, error) {
	if cfg.Identity == nil || cfg.Links == nil {
		return nil, errors.New("mesh: Identity and Links are required")
	}
	if err := CheckNickname(cfg.Nickname); err != nil {
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
		best:    newBestTTL(recentPerGen),
		peers:   make(map[PeerID]*peerInfo),
		pending: make(map[PeerID][]pendingPacket),
		senders: newLimiter[PeerID](senderRate, senderBurst, maxSenders),

		dupClosed: make(map[Fingerprint]time.Time),
	}
	n.keepalive, n.linkTimeout = keepaliveEvery, linkTimeout
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
		for fp, at := range n.dupClosed {
			if now.Sub(at) >= dupLinkCooldown {
				delete(n.dupClosed, fp)
			}
		}
		stale := n.staleLinksLocked()
		n.mu.Unlock()
		for _, l := range stale {
			n.log.Debug("link silent; closing", "peer", l.l.Peer())
			l.l.Close()
		}
	}
}

func (n *Node) addLink(ctx context.Context, tl transport.Link) {
	if tl.MTU() < MinMTU {
		n.log.Warn("link MTU too small", "peer", tl.Peer(), "mtu", tl.MTU())
		tl.Close()
		return
	}
	l := &link{l: tl, out: make(chan []byte, linkQueue), done: make(chan struct{})}
	l.lastRecv.Store(time.Now().UnixNano())
	n.mu.Lock()
	now := n.cfg.Now()
	l.created = now
	n.links[l] = true
	// Our announce goes first, even if the store has since dropped it: arriving
	// with the full TTL, it tells the neighbour who is on this link.
	if n.announceRaw != nil {
		n.sendLocked(l, n.announceRaw)
	}
	// Store-and-forward: a new neighbour gets everything still worth relaying,
	// oldest first.
	for _, s := range n.store {
		if now.Sub(s.at) < storeFor && !bytes.Equal(s.raw, n.announceRaw) {
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
	idle := time.NewTimer(n.keepalive)
	defer idle.Stop()
	for {
		frames := [][]byte{keepaliveFrame}
		select {
		case raw := <-l.out:
			frames = fragment(raw, l.l.MTU())
		case <-idle.C:
		case <-l.done:
			return
		}
		for _, f := range frames {
			if err := l.l.WriteFrame(f); err != nil {
				l.l.Close()
				return
			}
		}
		idle.Reset(n.keepalive)
	}
}

// staleLinksLocked returns links that have been silent for linkTimeout.
func (n *Node) staleLinksLocked() []*link {
	var out []*link
	cutoff := time.Now().Add(-n.linkTimeout).UnixNano()
	for l := range n.links {
		if l.lastRecv.Load() < cutoff {
			out = append(out, l)
		}
	}
	return out
}

func (n *Node) readLoop(l *link) {
	var asm assembler
	for {
		frame, err := l.l.ReadFrame()
		if err != nil {
			return
		}
		l.lastRecv.Store(time.Now().UnixNano())
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
	dup := n.attributeLocked(l, p, now)
	deliver = n.handleLocked(p, l, now)
	n.mu.Unlock()
	if dup != nil {
		n.log.Debug("duplicate link to a neighbour; closing the older", "peer", dup.l.Peer())
		dup.l.Close()
	}
	n.deliver(deliver)
}

// attributeLocked notes which neighbour is at the other end of l. Only the
// originator sends a packet with the full TTL, so a valid announce arriving
// with MaxTTL came from the device on this link. If another link already
// leads to that neighbour (a BLE device that changed its address is found
// and connected to again), it returns the older of the two to close.
func (n *Node) attributeLocked(l *link, p *Packet, now time.Time) *link {
	if p.Type != TypeAnnounce || p.TTL != MaxTTL ||
		p.Time.Before(now.Add(-maxAge)) || p.Time.After(now.Add(maxSkew)) {
		return nil
	}
	a, err := parseAnnounce(p.Payload)
	if err != nil {
		return nil
	}
	fp := FingerprintOf(a.signKey)
	if fp == l.neighbour || fp == n.id.Fingerprint() || !p.Verify(a.signKey) {
		return nil
	}
	l.neighbour = fp
	var other *link
	for o := range n.links {
		if o != l && o.neighbour == fp {
			other = o
			break
		}
	}
	if other == nil {
		return nil
	}
	if at, ok := n.dupClosed[fp]; ok && now.Sub(at) < dupLinkCooldown {
		return nil
	}
	n.dupClosed[fp] = now
	n.stats.DuplicateLinks++
	if l.created.Before(other.created) {
		return l
	}
	return other
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
	key := dedupKey(p)
	if n.seen.check(key) {
		n.stats.Duplicates++
		// Already handled, but this copy may reach further than the first.
		// A first copy that arrived with TTL 0 was neither relayed nor stored.
		forUs := p.Recipient != nil && n.mine(*p.Recipient)
		if old, ok := n.best.get(key); ok && p.TTL > old && !forUs && n.signatureOK(p) {
			n.best.set(key, p.TTL)
			n.relayLocked(p, from, now, old == 0)
		}
		return nil
	}
	n.best.set(key, p.TTL)
	if n.mine(p.Sender) {
		return nil // our own packet, back by another path
	}
	if !n.senders.allow(p.Sender, now) {
		n.stats.RateLimited++
		return nil
	}
	if !n.signatureOK(p) {
		return nil
	}
	if p.Recipient != nil && n.mine(*p.Recipient) {
		return n.dm.handle(n, p, now)
	}
	if p.Type == TypeAnnounce && !n.handleAnnounce(p, now) {
		return nil
	}
	n.relayLocked(p, from, now, true)
	switch p.Type {
	case TypeAnnounce:
		return n.flushPending(p.Sender, now)
	case TypeChannel:
		return n.handleChannel(p, from, now)
	}
	return nil
}

// signatureOK checks a signed packet from a sender we know before it is
// relayed, so forgeries die at the first hop that knows the real key.
// Announces carry their own key.
func (n *Node) signatureOK(p *Packet) bool {
	if p.Type == TypeAnnounce {
		a, err := parseAnnounce(p.Payload)
		if err != nil || !p.Verify(a.signKey) {
			n.stats.BadSigned++
			return false
		}
		return true
	}
	if !p.Type.signed() {
		return true
	}
	if peer := n.peers[p.Sender]; peer != nil && !p.Verify(peer.signKey) {
		n.stats.BadSigned++
		return false
	}
	return true
}

// relayLocked forwards p to every link but from and, if store is set, keeps
// it for neighbours who arrive later.
func (n *Node) relayLocked(p *Packet, from *link, now time.Time, store bool) {
	if p.TTL == 0 {
		return
	}
	q := *p
	q.TTL--
	raw := q.Encode()
	if store {
		n.storeLocked(raw, now)
	}
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
func (n *Node) sendStampedLocked(p *Packet) []byte {
	if p.Type.signed() {
		p.Sign(n.id.sign)
	}
	n.seen.check(dedupKey(p))
	n.best.set(dedupKey(p), p.TTL)
	raw := p.Encode()
	n.storeLocked(raw, p.Time)
	for l := range n.links {
		n.sendLocked(l, raw)
	}
	return raw
}

func (n *Node) announceLocked() {
	a := announce{signKey: n.id.SigningKey(), noiseKey: n.id.NoiseKey(), nickname: n.nickname}
	p := &Packet{Type: TypeAnnounce, Payload: a.encode()}
	n.stampLocked(p)
	n.announceRaw = n.sendStampedLocked(p)
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
