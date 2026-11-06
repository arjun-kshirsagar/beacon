package engine

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/reputation"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	// BlockSize is the size of the blocks we request.
	BlockSize = 16 << 10
	// MaxBlockSize is the largest block we serve to a peer.
	MaxBlockSize = 128 << 10

	defaultMaxConns   = 50
	uploadSlots       = 4 // unchoked peers, one of them optimistic
	rechokeInterval   = 10 * time.Second
	optimisticEvery   = 3 // rechokes between optimistic unchoke rotations
	redialAfter       = 5 * time.Minute
	maxConnsPerIP     = 2    // connections to or from one IP; limits Sybils behind one host
	maxQueue          = 1000 // addresses waiting to be dialed
	maxKnown          = 10000
	metadataExtID     = 1 // our ut_metadata extended message ID
	pexExtID          = 2 // our ut_pex extended message ID
	clientVersion     = "Beacon/0.2"
	dialTimeout       = 15 * time.Second
	ioTimeout         = 60 * time.Second
	idleTimeout       = 3 * time.Minute
	snubTimeout       = 60 * time.Second
	keepAliveInterval = 90 * time.Second
)

var (
	// ErrIncomplete reports that every peer failed before the download finished.
	ErrIncomplete = errors.New("engine: download incomplete: no usable peers left")
	// ErrBadPiece reports a piece that failed its hash check.
	ErrBadPiece = errors.New("engine: piece failed hash check")
	// ErrWrongTorrent reports a peer handshaking for a different info-hash.
	ErrWrongTorrent = errors.New("engine: peer is on a different torrent")
	// ErrBadRequest reports a peer requesting data we cannot or will not serve.
	ErrBadRequest = errors.New("engine: invalid block request")
	// ErrBanned reports a connection from or to a banned peer.
	ErrBanned = errors.New("engine: peer is banned")
)

// Config configures a Client.
type Config struct {
	Transport  transport.Transport
	PeerID     [20]byte // zero picks a random ID
	ListenPort uint16   // advertised to peers in the extension handshake
	MaxConns   int      // zero means 50
	Encryption Encryption
	// Reputation records peer behaviour; nil gives the client its own. Share one
	// between clients so a peer banned in one torrent is banned in all.
	Reputation *reputation.Book
	// AllowPrivatePeers lets the DHT and PEX supply private (RFC 1918)
	// addresses. Off by default, so strangers cannot steer us at hosts on our
	// own network. Trackers, LPD and AddPeers may always supply them.
	AllowPrivatePeers bool
	Logger            *slog.Logger
}

// Client downloads and seeds one torrent. Every connection, whether we dialed it
// or accepted it, both downloads and uploads.
type Client struct {
	t        *torrent.Torrent
	store    *Storage
	tr       transport.Transport
	peerID   [20]byte
	port     uint16
	maxConns int
	enc      Encryption
	rep      *reputation.Book
	private  bool // AllowPrivatePeers
	log      *slog.Logger
	maxMsg   uint32
	wake     chan struct{}

	mu         sync.Mutex
	pk         *picker
	conns      map[*peerConn]bool
	peerIDs    map[[20]byte]bool
	known      map[string]time.Time // last dial attempt per address
	queue      []*candidate         // addresses waiting to be dialed
	queued     map[string]*candidate
	dialing    int
	downloaded int64
	uploaded   int64
	verified   map[string]int64 // bytes of verified pieces, by sender's ban key (IP)
	done       chan struct{}    // closed once every piece is verified
}

// NewPeerID returns a random Azureus-style peer ID.
func NewPeerID() [20]byte {
	var id [20]byte
	copy(id[:], "-BC0002-")
	rand.Read(id[8:])
	return id
}

// New returns a client for t backed by store. It hashes the existing data first,
// so a partly downloaded torrent resumes and a complete one is ready to seed.
func New(t *torrent.Torrent, store *Storage, cfg Config) (*Client, error) {
	if cfg.Transport == nil {
		return nil, errors.New("engine: no transport configured")
	}
	have, err := Verify(t, store)
	if err != nil {
		return nil, err
	}
	c := &Client{
		t:        t,
		store:    store,
		tr:       cfg.Transport,
		peerID:   cfg.PeerID,
		port:     cfg.ListenPort,
		maxConns: cfg.MaxConns,
		enc:      cfg.Encryption,
		rep:      cfg.Reputation,
		private:  cfg.AllowPrivatePeers,
		log:      cfg.Logger,
		maxMsg:   uint32(max(1+len(have), 9+MaxBlockSize)),
		wake:     make(chan struct{}, 1),
		pk:       newPicker(t, have),
		conns:    make(map[*peerConn]bool),
		verified: make(map[string]int64),
		peerIDs:  make(map[[20]byte]bool),
		known:    make(map[string]time.Time),
		queued:   make(map[string]*candidate),
		done:     make(chan struct{}),
	}
	if c.peerID == ([20]byte{}) {
		c.peerID = NewPeerID()
	}
	if c.maxConns <= 0 {
		c.maxConns = defaultMaxConns
	}
	if c.rep == nil {
		c.rep = reputation.New(reputation.Config{})
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if have.Count() == t.NumPieces() {
		close(c.done)
	}
	return c, nil
}

// Torrent returns the torrent the client serves.
func (c *Client) Torrent() *torrent.Torrent { return c.t }

// PeerID returns the client's peer ID.
func (c *Client) PeerID() [20]byte { return c.peerID }

// Done is closed once the torrent is complete.
func (c *Client) Done() <-chan struct{} { return c.done }

// Stats describes a client's progress.
type Stats struct {
	Pieces, TotalPieces  int
	Downloaded, Uploaded int64
	Left                 int64
	Peers                int
	EncryptedPeers       int
}

// VerifiedFrom returns how many bytes of verified pieces each peer sent,
// keyed by IP address.
func (c *Client) VerifiedFrom() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.verified)
}

// PeerAddrs returns the listening addresses of connected peers that told us
// theirs, so others can be pointed at them.
func (c *Client) PeerAddrs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for pc := range c.conns {
		if pc.listenAddr != "" {
			out = append(out, pc.listenAddr)
		}
	}
	return out
}

// Stats returns current progress.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{
		Pieces: c.pk.have.Count(), TotalPieces: c.t.NumPieces(),
		Downloaded: c.downloaded, Uploaded: c.uploaded, Peers: len(c.conns),
	}
	for pc := range c.conns {
		if pc.encrypted {
			s.EncryptedPeers++
		}
	}
	for i := range c.t.NumPieces() {
		if !c.pk.have.Has(i) {
			s.Left += c.t.PieceSize(i)
		}
	}
	return s
}

func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// banKey identifies a peer for banning: its host, or the whole address if it
// has no port.
func banKey(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// AddPeers queues addresses the user supplied, with the highest priority.
func (c *Client) AddPeers(addrs ...string) { c.AddPeersFrom(SourceManual, addrs...) }

// AddPeersFrom queues addresses learned from src. Banned peers, addresses tried
// in the last few minutes, and addresses src may not supply are skipped. An
// address already queued gains src as another source, which raises its
// priority. When the queue is full, a new address replaces the lowest-priority
// one only if it outranks it.
func (c *Client) AddPeersFrom(src PeerSource, addrs ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for _, a := range addrs {
		if c.rep.Banned(banKey(a)) || !c.acceptAddr(src, a) {
			continue
		}
		if q := c.queued[a]; q != nil {
			q.sources |= src
			continue
		}
		if last, ok := c.known[a]; ok && now.Sub(last) < redialAfter {
			continue
		}
		cand := &candidate{addr: a, sources: src}
		if len(c.queue) >= maxQueue {
			low := 0
			for i, q := range c.queue {
				if q.priority() < c.queue[low].priority() {
					low = i
				}
			}
			if c.queue[low].priority() >= cand.priority() {
				continue
			}
			delete(c.queued, c.queue[low].addr)
			c.queue = slices.Delete(c.queue, low, low+1)
		}
		c.known[a] = now
		c.queue = append(c.queue, cand)
		c.queued[a] = cand
	}
	if len(c.known) > maxKnown {
		for a, t := range c.known {
			if now.Sub(t) >= redialAfter {
				delete(c.known, a)
			}
		}
	}
	c.signal()
}

func (c *Client) acceptAddr(src PeerSource, addr string) bool {
	return AcceptPeerAddr(src, addr, c.private)
}

// AcceptPeerAddr reports whether src may supply addr. Strangers (the DHT, PEX
// and trackers) may not point us at loopback or link-local addresses, and the
// DHT and PEX may not point us at private ones unless allowPrivate is set.
func AcceptPeerAddr(src PeerSource, addr string, allowPrivate bool) bool {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return src == SourceManual // host names come only from the user
	}
	ip := ap.Addr().Unmap()
	if ap.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	switch {
	case src == SourceManual:
		return true
	case ip.IsLoopback() || ip.IsLinkLocalUnicast():
		return false
	case ip.IsPrivate() && (src == SourceDHT || src == SourcePEX):
		return allowPrivate
	}
	return true
}

// next removes and returns the highest-priority queued address, oldest first
// among equals.
func (c *Client) next() string {
	best := 0
	for i, q := range c.queue {
		if q.priority() > c.queue[best].priority() {
			best = i
		}
	}
	cand := c.queue[best]
	c.queue = slices.Delete(c.queue, best, best+1)
	delete(c.queued, cand.addr)
	return cand.addr
}

// Run dials queued peers and runs the choker until ctx is done.
func (c *Client) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(rechokeInterval)
	defer tick.Stop()
	pexTick := time.NewTicker(pexInterval)
	defer pexTick.Stop()
	round := 0
	for {
		c.mu.Lock()
		for len(c.queue) > 0 && c.dialing+len(c.conns) < c.maxConns {
			addr := c.next()
			c.dialing++
			wg.Go(func() {
				err := c.dial(ctx, addr)
				if err != nil && ctx.Err() == nil {
					c.log.Debug("peer connection ended", "peer", addr, "err", err)
				}
			})
		}
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
		case <-tick.C:
			c.rechoke(round%optimisticEvery == 0)
			round++
		case <-pexTick.C:
			c.sendPEX()
		}
	}
}

func (c *Client) dial(ctx context.Context, addr string) error {
	conn, encrypted, err := secureDial(ctx, c.tr, addr, c.t.InfoHash, c.enc)
	if err != nil {
		c.mu.Lock()
		c.dialing--
		c.mu.Unlock()
		c.signal()
		return err
	}
	return c.runConn(ctx, conn, addr, true, encrypted)
}

// Serve accepts peers on l until ctx is done.
func (c *Client) Serve(ctx context.Context, l net.Listener) error {
	defer context.AfterFunc(ctx, func() { l.Close() })()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		addr := conn.RemoteAddr().String()
		c.mu.Lock()
		full := len(c.conns)+c.dialing >= c.maxConns+uploadSlots // leave room for incoming peers
		banned := c.rep.Banned(banKey(addr))
		if !full && !banned {
			c.dialing++
		}
		c.mu.Unlock()
		if full || banned {
			conn.Close()
			continue
		}
		wg.Go(func() {
			if err := c.runConn(ctx, conn, addr, false, false); err != nil && ctx.Err() == nil {
				c.log.Debug("peer connection ended", "peer", addr, "err", err)
			}
		})
	}
}

// Download fetches every missing piece, using peers and any peers added later
// with AddPeers. It returns nil once the torrent is complete and ErrIncomplete
// if every connection is gone and nobody is left to dial. Do not call Run while
// Download is running; it runs Run itself.
func (c *Client) Download(ctx context.Context, peers []string) error {
	select {
	case <-c.done:
		return nil
	default:
	}
	c.AddPeers(peers...)
	rctx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		c.Run(rctx)
		close(runDone)
	}()
	defer func() {
		cancel()
		<-runDone
	}()

	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-c.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
			c.mu.Lock()
			idle := len(c.conns) == 0 && c.dialing == 0 && len(c.queue) == 0
			c.mu.Unlock()
			if idle {
				select {
				case <-c.done:
					return nil
				default:
					return ErrIncomplete
				}
			}
		}
	}
}

// rechoke runs tit-for-tat: the interested peers that gave us the most data
// (or, when seeding, took the most) are unchoked, plus one random optimistic
// unchoke so new peers get a chance to prove themselves.
func (c *Client) rechoke(rotateOptimistic bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seeding := c.pk.missing() == 0
	var interested []*peerConn
	var optimistic *peerConn
	for pc := range c.conns {
		if pc.peerInterested {
			interested = append(interested, pc)
		}
		if pc.optimistic {
			optimistic = pc
		}
	}
	slices.SortFunc(interested, func(a, b *peerConn) int {
		if seeding {
			return cmp.Compare(b.rateUp, a.rateUp)
		}
		return cmp.Compare(b.rateDown, a.rateDown)
	})
	unchoke := map[*peerConn]bool{}
	for _, pc := range interested[:min(uploadSlots-1, len(interested))] {
		unchoke[pc] = true
	}
	if rotateOptimistic || optimistic == nil || !optimistic.peerInterested || unchoke[optimistic] {
		if optimistic != nil {
			optimistic.optimistic = false
		}
		optimistic = nil
		var rest []*peerConn
		for _, pc := range interested {
			if !unchoke[pc] {
				rest = append(rest, pc)
			}
		}
		if len(rest) > 0 {
			r, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rest))))
			optimistic = rest[r.Int64()]
			optimistic.optimistic = true
		}
	}
	if optimistic != nil {
		unchoke[optimistic] = true
	}
	for pc := range c.conns {
		pc.setChoking(!unchoke[pc])
		pc.rateDown, pc.rateUp = 0, 0
	}
}

// report records what key did and, if that bans it, drops its connections.
// It requires c.mu.
func (c *Client) report(key string, e reputation.Event) {
	already := c.rep.Banned(key)
	if !c.rep.Record(key, e) {
		return
	}
	if !already {
		c.log.Info("banning peer", "peer", key, "reason", e.String())
	}
	for pc := range c.conns {
		if pc.key == key {
			pc.close()
		}
	}
}

// pieceDone verifies a complete piece outside the lock, then stores or discards
// it and updates every connection.
func (c *Client) pieceDone(i int, ap *activePiece) {
	ok := c.t.Pieces[i] == sha1.Sum(ap.buf)
	var werr error
	if ok {
		_, werr = c.store.WriteAt(ap.buf, int64(i)*c.t.PieceLength)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case werr != nil:
		c.log.Error("writing piece failed", "piece", i, "err", werr)
		delete(c.pk.active, i)
	case !ok:
		senders := c.pk.failed(i, ap)
		c.log.Info("piece failed hash check", "piece", i, "senders", senders)
		if len(senders) == 1 {
			c.report(senders[0], reputation.BadPiece)
		} else {
			for _, s := range senders {
				c.report(s, reputation.SuspectPiece)
			}
		}
	default:
		for _, key := range c.pk.verified(i, ap.buf) {
			c.report(key, reputation.ProvenBad)
		}
		credited := map[string]bool{}
		for j, b := range ap.blocks {
			if b.source == nil {
				continue
			}
			c.verified[b.source.key] += int64(min(BlockSize, len(ap.buf)-j*BlockSize))
			if !credited[b.source.key] {
				credited[b.source.key] = true
				c.report(b.source.key, reputation.GoodPiece)
			}
		}
		c.downloaded += int64(len(ap.buf))
		for pc := range c.conns {
			pc.queue(peer.Have(uint32(i)))
			pc.updateInterest()
		}
		if c.pk.missing() == 0 {
			close(c.done)
			c.log.Info("download complete", "name", c.t.Name)
		}
	}
	for pc := range c.conns {
		pc.fill()
	}
}
