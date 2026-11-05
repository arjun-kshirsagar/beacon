package main

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/dht"
	"github.com/arjun-kshirsagar/beacon/core/engine"
	"github.com/arjun-kshirsagar/beacon/core/lpd"
	"github.com/arjun-kshirsagar/beacon/core/tracker"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	rediscoverDry = 15 * time.Second // retry soon when a round found nobody
	rediscover    = 5 * time.Minute
)

// discovery finds peers for one info-hash through trackers, the DHT and local
// discovery, and announces that we are in the swarm.
type discovery struct {
	infoHash [20]byte
	peerID   [20]byte
	trackers []string
	port     uint16
	node     *dht.Node  // nil when the DHT is off
	lpd      *lpdRouter // nil when local discovery is off
	tc       *tracker.Client
	log      *slog.Logger
	// progress reports bytes downloaded, uploaded and left; nil before the
	// torrent's size is known.
	progress func() (down, up, left int64)
}

func newTrackerClient() *tracker.Client {
	return tracker.NewClient(&transport.TCP{}, transport.UDP{})
}

// startDHT opens a DHT node on the given UDP port and joins the network
// through bootstrap (the public DHT routers if empty)
// in the background.
func startDHT(ctx context.Context, port uint16, bootstrap []string, log *slog.Logger) (*dht.Node, error) {
	if len(bootstrap) == 0 {
		bootstrap = dht.DefaultBootstrap
	}
	n, err := dht.New(dht.Config{
		Transport: transport.UDP{},
		Addr:      netip.AddrPortFrom(netip.IPv4Unspecified(), port).String(),
		Bootstrap: bootstrap,
		Logger:    log,
	})
	if err != nil {
		return nil, err
	}
	go n.Run(ctx)
	go func() {
		if err := n.Bootstrap(ctx); err != nil && ctx.Err() == nil {
			log.Warn("DHT bootstrap failed", "err", err)
			return
		}
		log.Info("joined DHT", "nodes", n.NumNodes())
	}()
	return n, nil
}

// foundFunc receives peer addresses and where they came from.
type foundFunc func(src engine.PeerSource, addrs []string)

// round announces once to every source and passes the peers found to found.
// It returns how long to wait before the next round.
func (d *discovery) round(ctx context.Context, ev tracker.Event, found foundFunc) time.Duration {
	req := tracker.Request{InfoHash: d.infoHash, PeerID: d.peerID, Port: d.port, Event: ev, Left: 1 << 30}
	if d.progress != nil {
		req.Downloaded, req.Uploaded, req.Left = d.progress()
	}
	var mu sync.Mutex
	wait, total := rediscover, 0
	report := func(src engine.PeerSource, ps []netip.AddrPort) {
		addrs := make([]string, len(ps))
		for i, p := range ps {
			addrs[i] = p.String()
		}
		mu.Lock()
		total += len(addrs)
		mu.Unlock()
		if len(addrs) > 0 {
			found(src, addrs)
		}
	}

	var wg sync.WaitGroup
	for _, u := range d.trackers {
		wg.Go(func() {
			resp, err := d.tc.Announce(ctx, u, req)
			if err != nil {
				d.log.Debug("announce failed", "tracker", u, "err", err)
				return
			}
			d.log.Debug("tracker answered", "tracker", u, "peers", len(resp.Peers))
			mu.Lock()
			wait = min(wait, resp.Interval)
			mu.Unlock()
			report(engine.SourceTracker, resp.Peers)
		})
	}
	if d.lpd != nil && ev != tracker.EventStopped {
		// Rate-limited inside the service; answers arrive through the router.
		if err := d.lpd.s.Announce(d.port, d.infoHash); err != nil {
			d.log.Debug("LPD announce", "err", err)
		}
	}
	if d.node != nil && ev != tracker.EventStopped {
		wg.Go(func() {
			ps, err := d.node.Announce(ctx, d.infoHash, d.port)
			if err != nil {
				d.log.Debug("DHT announce", "err", err)
			}
			d.log.Debug("DHT answered", "peers", len(ps))
			report(engine.SourceDHT, ps)
		})
	}
	wg.Wait()
	if total == 0 {
		return rediscoverDry
	}
	return wait
}

// run repeats discovery rounds until ctx is done, then tells trackers we left.
func (d *discovery) run(ctx context.Context, found foundFunc) {
	if d.lpd != nil {
		d.lpd.route(d.infoHash, found)
		defer d.lpd.unroute(d.infoHash)
	}
	ev := tracker.EventStarted
	for {
		wait := d.round(ctx, ev, found)
		ev = tracker.EventNone
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			d.round(sctx, tracker.EventStopped, func(engine.PeerSource, []string) {})
			cancel()
			return
		}
	}
}

// lpdRouter shares one local discovery socket among swarms, handing each
// announcement to the swarm for its info-hash.
type lpdRouter struct {
	s      *lpd.Service
	mu     sync.Mutex
	routes map[[20]byte]foundFunc
}

// startLPD joins the BEP 14 multicast group on the local network.
func startLPD(ctx context.Context, log *slog.Logger) (*lpdRouter, error) {
	s, err := lpd.New(lpd.Config{Transport: transport.UDP{}, Logger: log})
	if err != nil {
		return nil, err
	}
	r := &lpdRouter{s: s, routes: make(map[[20]byte]foundFunc)}
	go s.Run(ctx, func(ih [20]byte, p netip.AddrPort) {
		r.mu.Lock()
		fn := r.routes[ih]
		r.mu.Unlock()
		if fn != nil {
			log.Debug("LPD found peer", "peer", p)
			fn(engine.SourceLPD, []string{p.String()})
		}
	})
	return r, nil
}

func (r *lpdRouter) route(ih [20]byte, fn foundFunc) {
	r.mu.Lock()
	r.routes[ih] = fn
	r.mu.Unlock()
}

func (r *lpdRouter) unroute(ih [20]byte) {
	r.mu.Lock()
	delete(r.routes, ih)
	r.mu.Unlock()
}
