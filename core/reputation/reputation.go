package reputation

import (
	"sync"
	"time"
)

// Event is something a peer did.
type Event int

const (
	// GoodPiece: the peer sent part of a piece that verified.
	GoodPiece Event = iota
	// SuspectPiece: the peer was one of several senders of a corrupt piece.
	SuspectPiece
	// BadPiece: the peer was the only sender of a corrupt piece.
	BadPiece
	// ProvenBad: a block from the peer differed from the piece once verified.
	ProvenBad
	// ProtocolViolation: the peer sent a malformed or invalid message.
	ProtocolViolation
	// Flood: the peer exceeded a rate limit.
	Flood
	// Snubbed: the peer stopped sending data it had agreed to send.
	Snubbed
)

func (e Event) String() string {
	return [...]string{"good piece", "suspect piece", "bad piece", "proven bad block",
		"protocol violation", "flood", "snubbed"}[e]
}

const (
	// BanScore is the score at or below which a peer is banned.
	BanScore = -15
	maxScore = 20 // good history counts, but only up to a point
)

// delta is each event's effect on the score; bans marks events that ban at once.
var (
	delta = map[Event]int{GoodPiece: 1, SuspectPiece: -5, ProtocolViolation: -10, Flood: -10, Snubbed: -2}
	bans  = map[Event]bool{BadPiece: true, ProvenBad: true}
)

// Config configures a Book. Zero values pick the defaults.
type Config struct {
	BanDuration    time.Duration // first ban; default one hour
	MaxBanDuration time.Duration // cap on doubling; default one day
	MaxPeers       int           // records kept; default 10000
	Now            func() time.Time
}

// Book records peers' reputations. It is safe for concurrent use and may be
// shared by several torrents, so a peer banned in one is banned in all.
type Book struct {
	cfg   Config
	mu    sync.Mutex
	peers map[string]*record
}

type record struct {
	score       int
	bans        int
	bannedUntil time.Time
	lastSeen    time.Time
}

// New returns an empty Book.
func New(cfg Config) *Book {
	if cfg.BanDuration <= 0 {
		cfg.BanDuration = time.Hour
	}
	if cfg.MaxBanDuration <= 0 {
		cfg.MaxBanDuration = 24 * time.Hour
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Book{cfg: cfg, peers: make(map[string]*record)}
}

// Record applies e to key's reputation and reports whether key is now banned.
func (b *Book) Record(key string, e Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	r := b.get(key, now)
	if now.Before(r.bannedUntil) {
		return true
	}
	if bans[e] {
		b.ban(r, now)
		return true
	}
	r.score = min(r.score+delta[e], maxScore)
	if r.score <= BanScore {
		b.ban(r, now)
		return true
	}
	return false
}

// Ban bans key outright.
func (b *Book) Ban(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	b.ban(b.get(key, now), now)
}

// Banned reports whether key is banned now.
func (b *Book) Banned(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.peers[key]
	return r != nil && b.cfg.Now().Before(r.bannedUntil)
}

// Score returns key's current score.
func (b *Book) Score(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.peers[key]; r != nil {
		return r.score
	}
	return 0
}

// ban starts a ban twice as long as the last, and sets the score so that, once
// the ban ends, a little more misbehaviour bans again.
func (b *Book) ban(r *record, now time.Time) {
	d := b.cfg.BanDuration
	for range r.bans {
		if d >= b.cfg.MaxBanDuration {
			break
		}
		d *= 2
	}
	r.bans++
	r.bannedUntil = now.Add(min(d, b.cfg.MaxBanDuration))
	r.score = BanScore / 2
}

func (b *Book) get(key string, now time.Time) *record {
	r := b.peers[key]
	if r == nil {
		if len(b.peers) >= b.cfg.MaxPeers {
			b.prune(now)
		}
		r = &record{}
		b.peers[key] = r
	}
	r.lastSeen = now
	return r
}

// prune makes room by forgetting peers that are neither banned nor scored
// below zero, oldest first, then by halving the remaining unbanned records.
// Banned peers are never forgotten early.
func (b *Book) prune(now time.Time) {
	for k, r := range b.peers {
		if !now.Before(r.bannedUntil) && r.score >= 0 {
			delete(b.peers, k)
		}
	}
	if len(b.peers) < b.cfg.MaxPeers {
		return
	}
	dropped := 0
	for k, r := range b.peers {
		if dropped >= len(b.peers)/2 {
			break
		}
		if !now.Before(r.bannedUntil) {
			delete(b.peers, k)
			dropped++
		}
	}
}
