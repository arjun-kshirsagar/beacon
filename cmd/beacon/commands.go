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
	"strconv"
	"strings"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/engine"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/tracker"
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
	fmt.Printf("wrote %s\ninfo-hash %s\n", *out, hex.EncodeToString(t.InfoHash[:]))
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

// openClient opens storage for the torrent at path under dir and hashes it.
func openClient(path, dir string, tr transport.Transport, log *slog.Logger) (*torrent.Torrent, *engine.Client, func(), error) {
	t, err := loadTorrent(path)
	if err != nil {
		return nil, nil, nil, err
	}
	store, err := engine.OpenStorage(dir, t)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := engine.New(t, store, engine.Config{Transport: tr, Logger: log})
	if err != nil {
		store.Close()
		return nil, nil, nil, err
	}
	return t, c, func() { store.Close() }, nil
}

// announce asks every HTTP tracker of t for peers and returns their addresses.
func announce(ctx context.Context, t *torrent.Torrent, c *engine.Client, tr transport.Transport, port uint16, ev tracker.Event, log *slog.Logger) ([]string, time.Duration) {
	client := tracker.NewHTTPClient(tr)
	st := c.Stats()
	req := tracker.Request{
		InfoHash: t.InfoHash, PeerID: c.PeerID(), Port: port,
		Downloaded: st.Downloaded, Uploaded: st.Uploaded, Left: st.Left, Event: ev,
	}
	interval := tracker.DefaultInterval
	seen := map[string]bool{}
	var peers []string
	for _, u := range t.Trackers() {
		resp, err := tracker.Announce(ctx, client, u, req)
		if err != nil {
			log.Warn("announce failed", "tracker", u, "err", err)
			continue
		}
		interval = min(interval, resp.Interval)
		for _, p := range resp.Peers {
			if s := p.String(); !seen[s] {
				seen[s] = true
				peers = append(peers, s)
			}
		}
	}
	return peers, interval
}

func cmdGet(ctx context.Context, args []string) error {
	fs := newFlags("get", "<file.torrent>")
	dir := fs.String("o", ".", "directory to download into")
	port := fs.Uint("port", 6881, "port to report to trackers")
	verbose := fs.Bool("v", false, "verbose logging")
	var peerAddrs stringList
	fs.Var(&peerAddrs, "peer", "peer host:port to connect to (repeatable)")
	path, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	log := newLogger(*verbose)
	tr := &transport.TCP{}
	t, c, closeStore, err := openClient(path, *dir, tr, log)
	if err != nil {
		return err
	}
	defer closeStore()

	select {
	case <-c.Done():
		fmt.Println("already complete")
		return nil
	default:
	}

	peers := append([]string(nil), peerAddrs...)
	found, _ := announce(ctx, t, c, tr, uint16(*port), tracker.EventStarted, log)
	peers = append(peers, found...)
	if len(peers) == 0 {
		return errors.New("no peers: the torrent has no reachable HTTP tracker; pass -peer host:port")
	}
	log.Info("starting download", "name", t.Name, "peers", len(peers))

	stopProgress := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				st := c.Stats()
				fmt.Fprintf(os.Stderr, "\r%d/%d pieces (%.1f%%)", st.Pieces, st.TotalPieces,
					100*float64(t.Length-st.Left)/float64(t.Length))
			case <-stopProgress:
				return
			}
		}
	}()
	err = c.Download(ctx, peers)
	close(stopProgress)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	announce(ctx, t, c, tr, uint16(*port), tracker.EventCompleted, log)
	fmt.Printf("downloaded and verified %s\n", t.Name)
	return nil
}

func cmdSeed(ctx context.Context, args []string) error {
	fs := newFlags("seed", "<file.torrent>")
	dir := fs.String("dir", ".", "directory that contains the torrent's data")
	listen := fs.String("listen", ":6881", "address to accept peers on")
	verbose := fs.Bool("v", false, "verbose logging")
	path, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	log := newLogger(*verbose)
	tr := &transport.TCP{}
	t, c, closeStore, err := openClient(path, *dir, tr, log)
	if err != nil {
		return err
	}
	defer closeStore()
	select {
	case <-c.Done():
	default:
		st := c.Stats()
		return fmt.Errorf("data in %s is incomplete (%d/%d pieces verified)", *dir, st.Pieces, st.TotalPieces)
	}

	l, err := tr.Listen(*listen)
	if err != nil {
		return err
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	log.Info("seeding", "name", t.Name, "addr", l.Addr().String())

	go func() {
		ev := tracker.EventStarted
		for {
			_, interval := announce(ctx, t, c, tr, uint16(port), ev, log)
			ev = tracker.EventNone
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return
			}
		}
	}()

	err = c.Serve(ctx, l)
	// Tell trackers we are leaving; ctx is already cancelled, so use a fresh one.
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	announce(sctx, t, c, tr, uint16(port), tracker.EventStopped, log)
	return err
}
