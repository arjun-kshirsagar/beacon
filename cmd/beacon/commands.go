package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/dht"
	"github.com/arjun-kshirsagar/beacon/core/engine"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func newFlags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: beacon %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses flags and requires exactly one positional argument.
func parseArgs(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", errUsage // the flag package has already explained
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return "", errUsage
	}
	return fs.Arg(0), nil
}

func cmdCreate(args []string) error {
	fs := newFlags("create", "<file-or-dir>")
	pieceLen := fs.Int64("piece-length", torrent.DefaultPieceLength, "piece length in bytes")
	announce := fs.String("tracker", "", "announce URL to embed")
	out := fs.String("o", "", "output file (default <name>.torrent)")
	path, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	meta, err := torrent.Create(path, *pieceLen, *announce)
	if err != nil {
		return err
	}
	t, err := torrent.Parse(meta)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = t.Name + ".torrent"
	}
	if err := os.WriteFile(*out, meta, 0o644); err != nil {
		return err
	}
	m := torrent.Magnet{InfoHash: t.InfoHash, Name: t.Name, Trackers: t.Trackers()}
	fmt.Printf("wrote %s\ninfo-hash %s\nmagnet   %s\n", *out, hex.EncodeToString(t.InfoHash[:]), m.String())
	return nil
}

func loadTorrent(path string) (*torrent.Torrent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := torrent.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

func cmdInfo(args []string) error {
	fs := newFlags("info", "<file.torrent>")
	path, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	t, err := loadTorrent(path)
	if err != nil {
		return err
	}
	fmt.Printf("name:       %s\n", t.Name)
	fmt.Printf("info-hash:  %s\n", hex.EncodeToString(t.InfoHash[:]))
	fmt.Printf("size:       %d bytes\n", t.Length)
	fmt.Printf("pieces:     %d × %d bytes\n", t.NumPieces(), t.PieceLength)
	for _, u := range t.Trackers() {
		fmt.Printf("tracker:    %s\n", u)
	}
	if t.MultiFile {
		for _, f := range t.Files {
			fmt.Printf("  %10d  %s\n", f.Length, filepath.Join(f.Path...))
		}
	}
	return nil
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// swarmFlags are shared by get and seed.
type swarmFlags struct {
	port       *uint
	noDHT      *bool
	noLPD      *bool
	verbose    *bool
	encryption *string
	peers      stringList
}

func addSwarmFlags(fs *flag.FlagSet) *swarmFlags {
	sf := &swarmFlags{
		port:    fs.Uint("port", 6881, "TCP port for peers and UDP port for the DHT"),
		noDHT:   fs.Bool("no-dht", false, "do not use the DHT"),
		noLPD:   fs.Bool("no-lpd", false, "do not discover peers on the local network"),
		verbose: fs.Bool("v", false, "verbose logging"),
		encryption: fs.String("encryption", "prefer",
			"peer encryption (MSE): prefer, require, or off"),
	}
	fs.Var(&sf.peers, "peer", "peer host:port to connect to (repeatable)")
	return sf
}

// netOpts is what get and seed need to reach peers.
type netOpts struct {
	port  uint16
	node  *dht.Node  // nil when the DHT is off
	lpd   *lpdRouter // nil when local discovery is off
	peers []string   // extra peers to try
	enc   engine.Encryption
	log   *slog.Logger
}

// open turns parsed flags into netOpts, starting the DHT and local discovery
// unless they are off. Local discovery failing to start is not fatal.
func (sf *swarmFlags) open(ctx context.Context) (netOpts, error) {
	o := netOpts{port: uint16(*sf.port), peers: sf.peers, log: newLogger(*sf.verbose)}
	var err error
	if o.enc, err = engine.ParseEncryption(*sf.encryption); err != nil {
		return o, err
	}
	if !*sf.noDHT {
		if o.node, err = startDHT(ctx, o.port, o.log); err != nil {
			return o, fmt.Errorf("starting DHT: %w", err)
		}
	}
	if !*sf.noLPD {
		if o.lpd, err = startLPD(ctx, o.log); err != nil {
			o.log.Warn("local peer discovery unavailable", "err", err)
		}
	}
	return o, nil
}

// swarm is a running client with its listener, DHT node and peer discovery.
type swarm struct {
	t    *torrent.Torrent
	c    *engine.Client
	port uint16
	stop func()
}

// joinSwarm opens storage for t under dir, starts accepting peers, and starts
// discovering peers through trackers, the DHT and the given addresses.
func joinSwarm(ctx context.Context, t *torrent.Torrent, dir string, o netOpts) (*swarm, error) {
	port, node, local, log := o.port, o.node, o.lpd, o.log
	if t.Private {
		// BEP 27: a private torrent's peers come from its trackers only.
		node, local = nil, nil
	}
	tr := &transport.TCP{}
	l, err := tr.Listen(fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	if port == 0 { // any free port, as chat shares use
		port = uint16(l.Addr().(*net.TCPAddr).Port)
	}
	store, err := engine.OpenStorage(dir, t)
	if err != nil {
		l.Close()
		return nil, err
	}
	c, err := engine.New(t, store, engine.Config{Transport: tr, ListenPort: port, Encryption: o.enc, Logger: log})
	if err != nil {
		l.Close()
		store.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{}, 3)
	go func() { c.Serve(ctx, l); done <- struct{}{} }()
	go func() { c.Run(ctx); done <- struct{}{} }()
	c.AddPeers(o.peers...)
	d := &discovery{
		infoHash: t.InfoHash, peerID: c.PeerID(), trackers: t.Trackers(), port: port,
		node: node, lpd: local, tc: newTrackerClient(), log: log,
		progress: func() (int64, int64, int64) {
			st := c.Stats()
			return st.Downloaded, st.Uploaded, st.Left
		},
	}
	go func() {
		d.run(ctx, func(src engine.PeerSource, a []string) { c.AddPeersFrom(src, a...) })
		done <- struct{}{}
	}()
	log.Info("joined swarm", "name", t.Name, "port", port, "trackers", len(d.trackers),
		"dht", node != nil, "lpd", local != nil, "private", t.Private)

	return &swarm{t: t, c: c, port: port, stop: func() {
		cancel()
		for range 3 {
			<-done
		}
		store.Close()
	}}, nil
}

// resolveMagnet fetches a magnet link's metadata from peers found through its
// trackers, the DHT and o.peers.
func resolveMagnet(ctx context.Context, m *torrent.Magnet, o netOpts) (*torrent.Torrent, error) {
	port, node, log, enc := o.port, o.node, o.log, o.enc
	log.Info("fetching metadata", "info-hash", hex.EncodeToString(m.InfoHash[:]))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	peers := make(chan string, 1024)
	// The metadata phase dials peers too, so it applies the same address
	// filter as the engine.
	offer := func(src engine.PeerSource, addrs []string) {
		for _, a := range addrs {
			if !engine.AcceptPeerAddr(src, a, false) {
				continue
			}
			select {
			case peers <- a:
			default:
			}
		}
	}
	offer(engine.SourceManual, o.peers)
	offer(engine.SourceManual, m.Peers)
	d := &discovery{
		infoHash: m.InfoHash, peerID: engine.NewPeerID(), trackers: m.Trackers, port: port,
		node: node, lpd: o.lpd, tc: newTrackerClient(), log: log,
	}
	go d.run(ctx, offer)

	info, err := engine.FetchMetadata(ctx, &transport.TCP{}, m.InfoHash, peers, enc, log)
	if err != nil {
		return nil, err
	}
	return torrent.FromInfo(info, m.Trackers)
}

func cmdGet(ctx context.Context, args []string) error {
	fs := newFlags("get", "<file.torrent | magnet-link>")
	dir := fs.String("o", ".", "directory to download into")
	keepSeeding := fs.Bool("seed", false, "keep seeding after the download completes")
	sf := addSwarmFlags(fs)
	src, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	o, err := sf.open(ctx)
	if err != nil {
		return err
	}
	log := o.log

	var t *torrent.Torrent
	if strings.HasPrefix(src, "magnet:") {
		m, err := torrent.ParseMagnet(src)
		if err != nil {
			return err
		}
		if len(m.Trackers) == 0 && o.node == nil && len(m.Peers)+len(o.peers) == 0 {
			return errors.New("magnet link has no trackers or peers and the DHT is off")
		}
		if t, err = resolveMagnet(ctx, m, o); err != nil {
			return fmt.Errorf("fetching metadata: %w", err)
		}
		o.peers = append(o.peers, m.Peers...)
		meta := append(append([]byte("d4:info"), t.InfoBytes...), 'e')
		saved := filepath.Join(*dir, t.Name+".torrent")
		if err := os.MkdirAll(*dir, 0o755); err == nil && os.WriteFile(saved, meta, 0o644) == nil {
			log.Info("saved metadata", "file", saved)
		}
	} else if t, err = loadTorrent(src); err != nil {
		return err
	}

	s, err := joinSwarm(ctx, t, *dir, o)
	if err != nil {
		return err
	}
	defer s.stop()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for done := false; !done; {
		select {
		case <-s.c.Done():
			done = true
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr)
			return ctx.Err()
		case <-tick.C:
			st := s.c.Stats()
			fmt.Fprintf(os.Stderr, "\r%d/%d pieces (%.1f%%), %d peers (%d encrypted)   ", st.Pieces, st.TotalPieces,
				100*float64(t.Length-st.Left)/float64(t.Length), st.Peers, st.EncryptedPeers)
		}
	}
	fmt.Fprintln(os.Stderr)
	fmt.Printf("downloaded and verified %s\n", t.Name)
	if *keepSeeding {
		log.Info("seeding; press Ctrl-C to stop")
		<-ctx.Done()
	}
	return nil
}

func cmdSeed(ctx context.Context, args []string) error {
	fs := newFlags("seed", "<file.torrent>")
	dir := fs.String("dir", ".", "directory that contains the torrent's data")
	sf := addSwarmFlags(fs)
	path, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	t, err := loadTorrent(path)
	if err != nil {
		return err
	}
	o, err := sf.open(ctx)
	if err != nil {
		return err
	}
	log := o.log
	s, err := joinSwarm(ctx, t, *dir, o)
	if err != nil {
		return err
	}
	defer s.stop()
	select {
	case <-s.c.Done():
	default:
		st := s.c.Stats()
		return fmt.Errorf("data in %s is incomplete (%d/%d pieces verified)", *dir, st.Pieces, st.TotalPieces)
	}
	m := torrent.Magnet{InfoHash: t.InfoHash, Name: t.Name, Trackers: t.Trackers()}
	log.Info("seeding; press Ctrl-C to stop", "magnet", m.String())
	<-ctx.Done()
	st := s.c.Stats()
	log.Info("stopped", "uploaded", st.Uploaded)
	return nil
}
