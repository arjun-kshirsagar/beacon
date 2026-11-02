package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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
	port    *uint
	noDHT   *bool
	verbose *bool
	peers   stringList
}

func addSwarmFlags(fs *flag.FlagSet) *swarmFlags {
	sf := &swarmFlags{
		port:    fs.Uint("port", 6881, "TCP port for peers and UDP port for the DHT"),
		noDHT:   fs.Bool("no-dht", false, "do not use the DHT"),
		verbose: fs.Bool("v", false, "verbose logging"),
	}
	fs.Var(&sf.peers, "peer", "peer host:port to connect to (repeatable)")
	return sf
}

// swarm is a running client with its listener, DHT node and peer discovery.
type swarm struct {
	t    *torrent.Torrent
	c    *engine.Client
	stop func()
}

// joinSwarm opens storage for t under dir, starts accepting peers, and starts
// discovering peers through trackers, the DHT and the given addresses.
func joinSwarm(ctx context.Context, t *torrent.Torrent, dir string, port uint16, node *dht.Node, extra []string, log *slog.Logger) (*swarm, error) {
	tr := &transport.TCP{}
	l, err := tr.Listen(fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	store, err := engine.OpenStorage(dir, t)
	if err != nil {
		l.Close()
		return nil, err
	}
	c, err := engine.New(t, store, engine.Config{Transport: tr, ListenPort: port, Logger: log})
	if err != nil {
		l.Close()
		store.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{}, 3)
	go func() { c.Serve(ctx, l); done <- struct{}{} }()
	go func() { c.Run(ctx); done <- struct{}{} }()
	c.AddPeers(extra...)
	d := &discovery{
		infoHash: t.InfoHash, peerID: c.PeerID(), trackers: t.Trackers(), port: port,
		node: node, tc: newTrackerClient(), log: log,
		progress: func() (int64, int64, int64) {
			st := c.Stats()
			return st.Downloaded, st.Uploaded, st.Left
		},
	}
	go func() { d.run(ctx, func(a []string) { c.AddPeers(a...) }); done <- struct{}{} }()
	log.Info("joined swarm", "name", t.Name, "port", port, "trackers", len(d.trackers), "dht", node != nil)

	return &swarm{t: t, c: c, stop: func() {
		cancel()
		for range 3 {
			<-done
		}
		store.Close()
	}}, nil
}

// resolveMagnet fetches a magnet link's metadata from peers found through its
// trackers, the DHT and extra.
func resolveMagnet(ctx context.Context, m *torrent.Magnet, port uint16, node *dht.Node, extra []string, log *slog.Logger) (*torrent.Torrent, error) {
	log.Info("fetching metadata", "info-hash", hex.EncodeToString(m.InfoHash[:]))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	peers := make(chan string, 1024)
	offer := func(addrs []string) {
		for _, a := range addrs {
			select {
			case peers <- a:
			default:
			}
		}
	}
	offer(extra)
	offer(m.Peers)
	d := &discovery{
		infoHash: m.InfoHash, peerID: engine.NewPeerID(), trackers: m.Trackers, port: port,
		node: node, tc: newTrackerClient(), log: log,
	}
	go d.run(ctx, offer)

	info, err := engine.FetchMetadata(ctx, &transport.TCP{}, m.InfoHash, peers, log)
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
	log := newLogger(*sf.verbose)
	port := uint16(*sf.port)

	var node *dht.Node
	if !*sf.noDHT {
		if node, err = startDHT(ctx, port, log); err != nil {
			return fmt.Errorf("starting DHT: %w", err)
		}
	}

	var t *torrent.Torrent
	extra := sf.peers
	if strings.HasPrefix(src, "magnet:") {
		m, err := torrent.ParseMagnet(src)
		if err != nil {
			return err
		}
		if len(m.Trackers) == 0 && node == nil && len(m.Peers)+len(sf.peers) == 0 {
			return errors.New("magnet link has no trackers or peers and the DHT is off")
		}
		if t, err = resolveMagnet(ctx, m, port, node, sf.peers, log); err != nil {
			return fmt.Errorf("fetching metadata: %w", err)
		}
		extra = append(extra, m.Peers...)
		meta := append(append([]byte("d4:info"), t.InfoBytes...), 'e')
		saved := filepath.Join(*dir, t.Name+".torrent")
		if err := os.MkdirAll(*dir, 0o755); err == nil && os.WriteFile(saved, meta, 0o644) == nil {
			log.Info("saved metadata", "file", saved)
		}
	} else if t, err = loadTorrent(src); err != nil {
		return err
	}

	s, err := joinSwarm(ctx, t, *dir, port, node, extra, log)
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
			fmt.Fprintf(os.Stderr, "\r%d/%d pieces (%.1f%%), %d peers   ", st.Pieces, st.TotalPieces,
				100*float64(t.Length-st.Left)/float64(t.Length), st.Peers)
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
	log := newLogger(*sf.verbose)
	t, err := loadTorrent(path)
	if err != nil {
		return err
	}
	port := uint16(*sf.port)
	var node *dht.Node
	if !*sf.noDHT {
		if node, err = startDHT(ctx, port, log); err != nil {
			return fmt.Errorf("starting DHT: %w", err)
		}
	}
	s, err := joinSwarm(ctx, t, *dir, port, node, sf.peers, log)
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
