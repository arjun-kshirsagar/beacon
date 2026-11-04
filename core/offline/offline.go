// Package offline shares files between nearby devices with no internet: the
// mesh announces files and carries requests, and the torrent engine moves
// the data over a local group network such as Wi-Fi Direct.
//
// Alice shares a file: she seeds it and announces its info-hash on the mesh.
// Bob asks for it in an encrypted mesh message. Alice hosts a group (or uses
// the one she is in) and replies, encrypted, with its credentials and the
// peers in it. Bob joins the group and downloads, verifying every piece
// against the info-hash, then seeds and announces the file himself. Carol,
// asking later, is pointed at both and fetches from both at once.
//
// The radio is the platform's business: it implements Groups and reports
// back with GroupReady. See docs/protocol-spec.md, "Offline file transfer".
package offline

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/engine"
	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	joinTimeout     = 60 * time.Second // wait to join a group
	metadataTimeout = 60 * time.Second
	maxSeen         = 256       // shares remembered
	maxSize         = 8 << 30   // largest file fetched
	requestsPerMin  = 10        // requests answered per asker
	pieceLength     = 256 << 10 // for files we share
)

// askTimeout is how long to wait for an offer before asking someone else; a
// variable so tests can shorten it.
var askTimeout = 30 * time.Second

// Groups controls the local group network. Calls must not block: the platform
// answers with Service.GroupReady or Service.GroupFailed.
type Groups interface {
	// Host creates a group with these credentials.
	Host(network, passphrase string)
	// Join joins the group with these credentials.
	Join(network, passphrase string)
}

// Mesh is what the service needs from the mesh node.
type Mesh interface {
	SendDirectData(to mesh.Fingerprint, data []byte) error
	SendShare(infoHash [20]byte, name string, size int64) error
}

// Config configures a Service.
type Config struct {
	Mesh   Mesh
	Groups Groups
	// Dial connects to peers in the group.
	Dial transport.Transport
	// Listen returns a listener for a new swarm, reachable on the group.
	Listen func() (net.Listener, error)
	// Dir is where downloads are saved.
	Dir    string
	Logger *slog.Logger
}

// Service runs offline file sharing for one device.
type Service struct {
	cfg    Config
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	seen     map[[20]byte]*seenShare
	swarms   map[[20]byte]*swarm
	fetches  map[[20]byte]*fetch
	group    *group
	requests map[mesh.Fingerprint][]time.Time
	strikes  map[mesh.Fingerprint]*strike
}

type seenShare struct {
	name, nickname string
	size           int64
	from           map[mesh.Fingerprint]time.Time
	at             time.Time
}

type swarm struct {
	t      *torrent.Torrent
	c      *engine.Client
	port   uint16
	path   string
	shared bool // we announced it ourselves rather than fetching it
	stop   func()
}

type fetch struct {
	infoHash  [20]byte
	name      string
	state     string
	asked     mesh.Fingerprint
	tried     map[mesh.Fingerprint]bool
	timer     *time.Timer
	peers     []netip.AddrPort // from the offer, while joining
	offeredBy mesh.Fingerprint // whose offer we followed
	err       error
}

type group struct {
	network, passphrase string
	host                bool
	ip                  netip.Addr // valid once ready
	ready               bool
	waiting             []pendingOffer // requests to answer once ready
	timer               *time.Timer
}

type pendingOffer struct {
	to       mesh.Fingerprint
	infoHash [20]byte
}

// New returns a service. Close stops it.
func New(cfg Config) *Service {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{cfg: cfg, log: cfg.Logger, ctx: ctx, cancel: cancel,
		seen: make(map[[20]byte]*seenShare), swarms: make(map[[20]byte]*swarm),
		fetches: make(map[[20]byte]*fetch), requests: make(map[mesh.Fingerprint][]time.Time),
		strikes: make(map[mesh.Fingerprint]*strike)}
}

// Close stops every swarm.
func (s *Service) Close() {
	s.cancel()
	s.mu.Lock()
	swarms := slices.Collect(maps.Values(s.swarms))
	s.mu.Unlock()
	for _, sw := range swarms {
		sw.stop()
	}
}

// Share seeds the file or directory at path and announces it to the mesh.
func (s *Service) Share(path string) ([20]byte, error) {
	meta, err := torrent.Create(path, pieceLength, "")
	if err != nil {
		return [20]byte{}, err
	}
	t, err := torrent.Parse(meta)
	if err != nil {
		return [20]byte{}, err
	}
	sw, err := s.startSwarm(t, filepath.Dir(path), nil)
	if err != nil {
		return t.InfoHash, err
	}
	select {
	case <-sw.c.Done():
	default:
		sw.stop()
		return t.InfoHash, fmt.Errorf("offline: %s changed while being read", path)
	}
	sw.shared = true
	s.mu.Lock()
	if old := s.swarms[t.InfoHash]; old != nil {
		s.mu.Unlock()
		sw.stop()
		return t.InfoHash, s.cfg.Mesh.SendShare(t.InfoHash, t.Name, t.Length)
	}
	s.swarms[t.InfoHash] = sw
	s.mu.Unlock()
	return t.InfoHash, s.cfg.Mesh.SendShare(t.InfoHash, t.Name, t.Length)
}

// startSwarm opens storage for t under dir and starts seeding or downloading.
func (s *Service) startSwarm(t *torrent.Torrent, dir string, peers []string) (*swarm, error) {
	l, err := s.cfg.Listen()
	if err != nil {
		return nil, err
	}
	port, err := listenPort(l)
	if err != nil {
		l.Close()
		return nil, err
	}
	store, err := engine.OpenStorage(dir, t)
	if err != nil {
		l.Close()
		return nil, err
	}
	// The group is a private network by design, so peers may have private
	// addresses wherever they come from.
	c, err := engine.New(t, store, engine.Config{Transport: s.cfg.Dial, ListenPort: port,
		AllowPrivatePeers: true, Logger: s.log})
	if err != nil {
		l.Close()
		store.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(s.ctx)
	var wg sync.WaitGroup
	wg.Go(func() { c.Serve(ctx, l) })
	wg.Go(func() { c.Run(ctx) })
	c.AddPeers(peers...)
	var once sync.Once
	return &swarm{t: t, c: c, port: port, path: filepath.Join(dir, t.Name), stop: func() {
		once.Do(func() {
			cancel()
			l.Close()
			wg.Wait()
			store.Close()
		})
	}}, nil
}

func listenPort(l net.Listener) (uint16, error) {
	_, p, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(p, 10, 16)
	return uint16(n), err
}

// OnShare records a file announced on the mesh. Wire it to mesh.Config.OnShare.
func (s *Service) OnShare(sh mesh.Share) {
	if sh.Size <= 0 || sh.Size > maxSize {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.distrustedLocked(sh.From) {
		return
	}
	e := s.seen[sh.InfoHash]
	if e == nil {
		if len(s.seen) >= maxSeen {
			s.forgetOldestLocked()
		}
		e = &seenShare{name: sh.Name, nickname: sh.Nickname, size: sh.Size, from: map[mesh.Fingerprint]time.Time{}}
		s.seen[sh.InfoHash] = e
	}
	if len(e.from) < 64 {
		e.from[sh.From] = sh.Time
	}
	e.at = time.Now()
}

func (s *Service) forgetOldestLocked() {
	var oldest [20]byte
	var at time.Time
	for ih, e := range s.seen {
		if at.IsZero() || e.at.Before(at) {
			oldest, at = ih, e.at
		}
	}
	delete(s.seen, oldest)
}

// OnData handles a request or offer from the mesh. Wire it to
// mesh.Config.OnData.
func (s *Service) OnData(from mesh.Fingerprint, data []byte) {
	req, off, err := parseMessage(data)
	if err != nil {
		s.log.Debug("ignoring offline message", "from", from.Short(), "err", err)
		return
	}
	if req != nil {
		s.handleRequest(from, req.infoHash)
	} else {
		s.handleOffer(from, off)
	}
}

func (s *Service) handleRequest(from mesh.Fingerprint, ih [20]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.swarms[ih] == nil || !s.allowRequestLocked(from) {
		return
	}
	g := s.group
	switch {
	case g == nil:
		// Host a group of our own for the asker to join.
		g = &group{network: "DIRECT-bc-" + randomString(6), passphrase: randomString(16), host: true}
		s.group = g
		g.waiting = append(g.waiting, pendingOffer{from, ih})
		g.timer = time.AfterFunc(joinTimeout, func() { s.GroupFailed("timed out") })
		s.log.Info("hosting a group for a request", "network", g.network)
		go s.cfg.Groups.Host(g.network, g.passphrase)
	case !g.ready:
		g.waiting = append(g.waiting, pendingOffer{from, ih})
	default:
		s.sendOfferLocked(from, ih)
	}
}

func (s *Service) allowRequestLocked(from mesh.Fingerprint) bool {
	now := time.Now()
	recent := slices.DeleteFunc(s.requests[from], func(t time.Time) bool { return now.Sub(t) > time.Minute })
	if len(recent) >= requestsPerMin {
		s.requests[from] = recent
		return false
	}
	if len(s.requests) > 1024 {
		clear(s.requests)
	}
	s.requests[from] = append(recent, now)
	return true
}

// sendOfferLocked points from at our swarm for ih: us and every peer we know
// on the group's network.
func (s *Service) sendOfferLocked(to mesh.Fingerprint, ih [20]byte) {
	sw, g := s.swarms[ih], s.group
	if sw == nil || g == nil || !g.ready {
		return
	}
	o := offer{infoHash: ih, network: g.network, passphrase: g.passphrase,
		peers: []netip.AddrPort{netip.AddrPortFrom(g.ip, sw.port)}}
	for _, a := range sw.c.PeerAddrs() {
		if p, err := netip.ParseAddrPort(a); err == nil && sameSubnet(p.Addr(), g.ip) && !slices.Contains(o.peers, p) &&
			len(o.peers) < maxOfferPeers {
			o.peers = append(o.peers, p)
		}
	}
	if err := s.cfg.Mesh.SendDirectData(to, o.encode()); err != nil {
		s.log.Warn("sending an offer", "to", to.Short(), "err", err)
	}
}

// sameSubnet reports whether a is in b's /24, as group networks are.
func sameSubnet(a, b netip.Addr) bool {
	a, b = a.Unmap(), b.Unmap()
	if !a.Is4() || !b.Is4() {
		return false
	}
	x, y := a.As4(), b.As4()
	return x[0] == y[0] && x[1] == y[1] && x[2] == y[2]
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// Get fetches a file announced on the mesh.
func (s *Service) Get(ih [20]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.swarms[ih] != nil {
		return nil
	}
	if f := s.fetches[ih]; f != nil && f.err == nil {
		return nil
	}
	e := s.seen[ih]
	if e == nil {
		return errors.New("offline: nobody nearby has announced that file")
	}
	f := &fetch{infoHash: ih, name: e.name, tried: map[mesh.Fingerprint]bool{}}
	s.fetches[ih] = f
	s.askNextLocked(f)
	return f.err
}

// askNextLocked asks the most recent announcer not yet tried for an offer.
func (s *Service) askNextLocked(f *fetch) {
	var who mesh.Fingerprint
	var at time.Time
	if e := s.seen[f.infoHash]; e != nil {
		for fp, t := range e.from {
			if !f.tried[fp] && t.After(at) {
				who, at = fp, t
			}
		}
	}
	if who == "" {
		f.state, f.err = "failed", errors.New("offline: nobody answered")
		return
	}
	f.tried[who] = true
	f.asked, f.state = who, "asking"
	if err := s.cfg.Mesh.SendDirectData(who, request{infoHash: f.infoHash}.encode()); err != nil {
		s.log.Debug("asking for a file", "who", who.Short(), "err", err)
	}
	if f.timer != nil {
		f.timer.Stop()
	}
	f.timer = time.AfterFunc(askTimeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fetches[f.infoHash] == f && f.state == "asking" {
			s.strikeLocked(f.asked, f.infoHash, "no offer")
			s.askNextLocked(f)
		}
	})
}

// A device that announces files it then fails to deliver (no offer, or an
// offer that leads nowhere) gets a strike. Its announcement of that file is
// forgotten at once, and after maxStrikes it is ignored altogether for a
// while, so fake announcements cannot keep sending us after nothing.
const (
	maxStrikes  = 3
	strikeReset = time.Hour
)

type strike struct {
	count int
	last  time.Time
}

func (s *Service) strikeLocked(fp mesh.Fingerprint, ih [20]byte, why string) {
	if fp == "" {
		return
	}
	st := s.strikes[fp]
	if st == nil || time.Since(st.last) > strikeReset {
		if len(s.strikes) >= 1024 {
			clear(s.strikes)
		}
		st = &strike{}
		s.strikes[fp] = st
	}
	st.count++
	st.last = time.Now()
	s.log.Info("announcer failed to deliver", "who", fp.Short(), "why", why, "strikes", st.count)
	forget := func(ih [20]byte, e *seenShare) {
		delete(e.from, fp)
		if len(e.from) == 0 && s.swarms[ih] == nil {
			delete(s.seen, ih)
		}
	}
	if e := s.seen[ih]; e != nil {
		forget(ih, e)
	}
	if st.count >= maxStrikes {
		for other, e := range s.seen {
			forget(other, e)
		}
	}
}

func (s *Service) distrustedLocked(fp mesh.Fingerprint) bool {
	st := s.strikes[fp]
	return st != nil && st.count >= maxStrikes && time.Since(st.last) <= strikeReset
}

func (s *Service) handleOffer(from mesh.Fingerprint, o *offer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fetches[o.infoHash]
	// Only the device we asked may tell us where to connect.
	if f == nil || f.state != "asking" || f.asked != from {
		return
	}
	f.timer.Stop()
	f.offeredBy = from
	g := s.group
	switch {
	case g != nil && g.network == o.network && g.ready:
		s.transferLocked(f, o.peers)
	case g != nil && g.network != o.network:
		// One group at a time; the file is fetched later or from someone
		// in our group.
		f.state, f.err = "failed", errors.New("offline: already in another group")
	default:
		f.state, f.peers = "joining", o.peers
		if g == nil {
			g = &group{network: o.network, passphrase: o.passphrase}
			s.group = g
			g.timer = time.AfterFunc(joinTimeout, func() { s.GroupFailed("timed out") })
			s.log.Info("joining a group for a download", "network", g.network)
			go s.cfg.Groups.Join(g.network, g.passphrase)
		}
	}
}

// GroupReady reports that we are in the group with address ip. Call it from
// the platform after Groups.Host or Groups.Join succeeds.
func (s *Service) GroupReady(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Unmap().Is4() {
		s.GroupFailed("bad address " + ip)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.group
	if g == nil {
		return
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	g.ip, g.ready = addr.Unmap(), true
	for _, w := range g.waiting {
		s.sendOfferLocked(w.to, w.infoHash)
	}
	g.waiting = nil
	for _, f := range s.fetches {
		if f.state == "joining" {
			s.transferLocked(f, f.peers)
		}
	}
}

// GroupFailed reports that hosting or joining the group failed.
func (s *Service) GroupFailed(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group == nil || s.group.ready {
		return
	}
	s.log.Warn("group failed", "reason", reason)
	s.group = nil
	for _, f := range s.fetches {
		if f.state == "joining" {
			f.state, f.err = "failed", fmt.Errorf("offline: joining the group: %s", reason)
		}
	}
}

// GroupGone reports that we left the group or it dissolved.
func (s *Service) GroupGone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.group = nil
}

// transferLocked fetches metadata and data from peers on our group.
func (s *Service) transferLocked(f *fetch, offered []netip.AddrPort) {
	g := s.group
	var peers []string
	for _, p := range offered {
		// Only ever connect inside the group's network, wherever the offer
		// says, and never to ourselves.
		if sameSubnet(p.Addr(), g.ip) && p.Addr() != g.ip {
			peers = append(peers, p.String())
		}
	}
	if len(peers) == 0 {
		f.state, f.err = "failed", errors.New("offline: no peers in the group")
		s.strikeLocked(f.offeredBy, f.infoHash, "offered no reachable peers")
		return
	}
	f.state, f.peers = "fetching", nil
	go func() {
		err := s.download(f, peers)
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil && s.ctx.Err() == nil {
			f.state, f.err = "failed", err
			s.strikeLocked(f.offeredBy, f.infoHash, err.Error())
			s.log.Warn("download failed", "name", f.name, "err", err)
		}
	}()
}

func (s *Service) download(f *fetch, peers []string) error {
	ctx, cancel := context.WithTimeout(s.ctx, metadataTimeout)
	defer cancel()
	ch := make(chan string, len(peers))
	for _, p := range peers {
		ch <- p
	}
	info, err := engine.FetchMetadata(ctx, s.cfg.Dial, f.infoHash, ch, engine.EncryptPrefer, s.log)
	if err != nil {
		return fmt.Errorf("offline: fetching the file's details: %w", err)
	}
	t, err := torrent.FromInfo(info, nil)
	if err != nil {
		return err
	}
	if t.Length > maxSize {
		return fmt.Errorf("offline: %s is too large (%d bytes)", t.Name, t.Length)
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o755); err != nil {
		return err
	}
	sw, err := s.startSwarm(t, s.cfg.Dir, peers)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		sw.stop()
		return nil
	}
	s.swarms[f.infoHash] = sw
	f.name, f.state = t.Name, "downloading"
	s.mu.Unlock()
	select {
	case <-sw.c.Done():
	case <-s.ctx.Done():
		return nil
	}
	s.mu.Lock()
	f.state = "seeding"
	s.mu.Unlock()
	s.log.Info("downloaded and verified; announcing", "name", t.Name)
	// Now we can serve it too: say so, so the next asker fetches from us
	// as well.
	return s.cfg.Mesh.SendShare(f.infoHash, t.Name, t.Length)
}

// SeenShare is a file announced on the mesh.
type SeenShare struct {
	InfoHash string `json:"infoHash"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	From     string `json:"from"` // nickname of the first announcer
	Sources  int    `json:"sources"`
	Have     bool   `json:"have"`
}

// Seen lists files announced on the mesh, newest first.
func (s *Service) Seen() []SeenShare {
	s.mu.Lock()
	defer s.mu.Unlock()
	type item struct {
		SeenShare
		at time.Time
	}
	var items []item
	for ih, e := range s.seen {
		_, have := s.swarms[ih]
		items = append(items, item{SeenShare{hex.EncodeToString(ih[:]), e.name, e.size, e.nickname, len(e.from), have}, e.at})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.After(items[j].at) })
	out := make([]SeenShare, len(items))
	for i, it := range items {
		out[i] = it.SeenShare
	}
	return out
}

// Transfer describes a file we share, fetch or seed.
type Transfer struct {
	InfoHash    string           `json:"infoHash"`
	Name        string           `json:"name"`
	State       string           `json:"state"` // sharing, asking, joining, fetching, downloading, seeding, failed
	Pieces      int              `json:"pieces"`
	TotalPieces int              `json:"totalPieces"`
	Peers       int              `json:"peers"`
	Uploaded    int64            `json:"uploaded"`
	From        map[string]int64 `json:"from,omitempty"` // verified bytes by sender IP
	Path        string           `json:"path,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// Transfers lists what we share and fetch.
func (s *Service) Transfers() []Transfer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Transfer
	for ih, sw := range s.swarms {
		st := sw.c.Stats()
		state := "seeding"
		if sw.shared {
			state = "sharing"
		} else if st.Pieces < st.TotalPieces {
			state = "downloading"
		}
		out = append(out, Transfer{InfoHash: hex.EncodeToString(ih[:]), Name: sw.t.Name, State: state,
			Pieces: st.Pieces, TotalPieces: st.TotalPieces, Peers: st.Peers, Uploaded: st.Uploaded,
			From: sw.c.VerifiedFrom(), Path: sw.path})
	}
	for ih, f := range s.fetches {
		if s.swarms[ih] != nil {
			continue
		}
		t := Transfer{InfoHash: hex.EncodeToString(ih[:]), Name: f.name, State: f.state}
		if f.err != nil {
			t.Error = f.err.Error()
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
