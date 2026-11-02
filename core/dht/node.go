package dht

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	alpha           = 6 // concurrent queries per lookup; many public nodes never answer
	maxCandidates   = 256
	maxLookupPeers  = 512
	maxPeersPerHash = 200
	maxHashes       = 10000
	peerTTL         = 30 * time.Minute
	secretRotation  = 5 * time.Minute
	refreshInterval = 5 * time.Minute
	maxPacket       = 8 << 10
	maxValues       = 50 // peers returned per get_peers response
)

// DefaultBootstrap lists well-known routers of the public DHT.
var DefaultBootstrap = []string{
	"router.bittorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"router.utorrent.com:6881",
}

var (
	// ErrNoNodes reports a lookup with an empty routing table.
	ErrNoNodes = errors.New("dht: no known nodes")
	// ErrTimeout reports an unanswered query.
	ErrTimeout = errors.New("dht: query timed out")
)

// Config configures a Node.
type Config struct {
	Transport    transport.PacketTransport
	Addr         string // listen address
	ID           ID     // zero picks a random ID
	Bootstrap    []string
	QueryTimeout time.Duration // zero means two seconds
	Logger       *slog.Logger
}

// Node is a DHT node: it answers other nodes' queries and runs lookups.
type Node struct {
	id      ID
	conn    net.PacketConn
	tr      transport.PacketTransport
	timeout time.Duration
	boot    []string
	log     *slog.Logger

	mu         sync.Mutex
	table      table
	pending    map[string]*call
	peers      map[ID]map[netip.AddrPort]time.Time
	secret     [2][16]byte // current and previous token secrets
	lastRotate time.Time
}

type call struct {
	addr string
	done chan *message
}

// New opens the node's socket. Call Run to start serving.
func New(cfg Config) (*Node, error) {
	if cfg.Transport == nil {
		return nil, errors.New("dht: no transport configured")
	}
	conn, err := cfg.Transport.ListenPacket(cfg.Addr)
	if err != nil {
		return nil, err
	}
	n := &Node{
		id:         cfg.ID,
		conn:       conn,
		tr:         cfg.Transport,
		timeout:    cfg.QueryTimeout,
		boot:       cfg.Bootstrap,
		log:        cfg.Logger,
		pending:    make(map[string]*call),
		peers:      make(map[ID]map[netip.AddrPort]time.Time),
		lastRotate: time.Now(),
	}
	if n.id == (ID{}) {
		n.id = RandomID()
	}
	if n.timeout == 0 {
		n.timeout = 2 * time.Second
	}
	if n.log == nil {
		n.log = slog.New(slog.DiscardHandler)
	}
	n.table.self = n.id
	rand.Read(n.secret[0][:])
	rand.Read(n.secret[1][:])
	return n, nil
}

// ID returns the node's ID.
func (n *Node) ID() ID { return n.id }

// Addr returns the node's local address.
func (n *Node) Addr() net.Addr { return n.conn.LocalAddr() }

// NumNodes returns the size of the routing table.
func (n *Node) NumNodes() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.table.len()
}

// Run serves queries and delivers responses until ctx is done, then closes the
// socket.
func (n *Node) Run(ctx context.Context) error {
	defer n.conn.Close()
	defer context.AfterFunc(ctx, func() { n.conn.Close() })()
	go n.maintain(ctx)
	buf := make([]byte, maxPacket)
	for {
		size, from, err := n.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		addr, err := netip.ParseAddrPort(from.String())
		if err != nil {
			continue
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if !validAddr(addr) {
			continue
		}
		m, err := parseMessage(buf[:size])
		if err != nil {
			continue
		}
		if m.Y == "q" {
			n.handleQuery(m, from, addr)
			continue
		}
		n.mu.Lock()
		c := n.pending[m.T]
		if c != nil && c.addr == from.String() {
			delete(n.pending, m.T)
		} else {
			if c != nil {
				n.log.Debug("dht reply from unexpected address", "want", c.addr, "got", from)
			}
			c = nil // unknown transaction, or a reply from the wrong address
		}
		n.mu.Unlock()
		if c != nil {
			c.done <- m
		}
	}
}

func (n *Node) maintain(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastRefresh := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			n.mu.Lock()
			if now.Sub(n.lastRotate) >= secretRotation {
				n.secret[1] = n.secret[0]
				rand.Read(n.secret[0][:])
				n.lastRotate = now
			}
			for h, ps := range n.peers {
				for p, exp := range ps {
					if now.After(exp) {
						delete(ps, p)
					}
				}
				if len(ps) == 0 {
					delete(n.peers, h)
				}
			}
			size := n.table.len()
			n.mu.Unlock()
			if size < K && len(n.boot) > 0 {
				n.Bootstrap(ctx)
			} else if now.Sub(lastRefresh) >= refreshInterval {
				n.lookup(ctx, RandomID(), false)
				lastRefresh = now
			}
		}
	}
}

func (n *Node) token(ip netip.Addr, secret [16]byte) string {
	mac := hmac.New(sha256.New, secret[:])
	b := ip.As16()
	mac.Write(b[:])
	return string(mac.Sum(nil)[:8])
}

func (n *Node) validToken(ip netip.Addr, tok string) bool {
	n.mu.Lock()
	secrets := n.secret
	n.mu.Unlock()
	for _, s := range secrets {
		if hmac.Equal([]byte(tok), []byte(n.token(ip, s))) {
			return true
		}
	}
	return false
}

func (n *Node) send(b []byte, to net.Addr) {
	if _, err := n.conn.WriteTo(b, to); err != nil {
		n.log.Debug("dht send failed", "to", to, "err", err)
	}
}

func (n *Node) handleQuery(m *message, from net.Addr, addr netip.AddrPort) {
	sender, ok := id20(m.A, "id")
	if !ok {
		n.send(encodeError(m.T, errProtocol, "missing id"), from)
		return
	}
	r := map[string]any{"id": string(n.id[:])}
	switch m.Q {
	case "ping":
	case "find_node":
		target, ok := id20(m.A, "target")
		if !ok {
			n.send(encodeError(m.T, errProtocol, "missing target"), from)
			return
		}
		n.mu.Lock()
		r["nodes"] = string(encodeNodes(n.table.closest(target, K)))
		n.mu.Unlock()
	case "get_peers":
		ih, ok := id20(m.A, "info_hash")
		if !ok {
			n.send(encodeError(m.T, errProtocol, "missing info_hash"), from)
			return
		}
		n.mu.Lock()
		r["token"] = n.token(addr.Addr(), n.secret[0])
		var values []any
		for p := range n.peers[ih] {
			if len(values) == maxValues {
				break
			}
			values = append(values, encodePeer(p))
		}
		r["nodes"] = string(encodeNodes(n.table.closest(ih, K)))
		n.mu.Unlock()
		if len(values) > 0 {
			r["values"] = values
		}
	case "announce_peer":
		ih, ok := id20(m.A, "info_hash")
		tok, _ := m.A["token"].(string)
		port, _ := m.A["port"].(int64)
		if implied, _ := m.A["implied_port"].(int64); implied == 1 {
			port = int64(addr.Port())
		}
		if !ok || port <= 0 || port > 65535 {
			n.send(encodeError(m.T, errProtocol, "bad announce"), from)
			return
		}
		if !n.validToken(addr.Addr(), tok) {
			n.send(encodeError(m.T, errProtocol, "bad token"), from)
			return
		}
		n.storePeer(ih, netip.AddrPortFrom(addr.Addr(), uint16(port)))
	default:
		n.send(encodeError(m.T, errMethod, "method unknown"), from)
		return
	}
	n.send(encodeResponse(m.T, r), from)

	if ro, _ := m.A["ro"].(int64); ro != 1 {
		n.mu.Lock()
		n.table.seen(Contact{ID: sender, Addr: addr}, time.Now())
		n.mu.Unlock()
	}
}

func (n *Node) storePeer(ih ID, p netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peers[ih]
	if ps == nil {
		if len(n.peers) >= maxHashes {
			return
		}
		ps = make(map[netip.AddrPort]time.Time)
		n.peers[ih] = ps
	}
	if _, ok := ps[p]; !ok && len(ps) >= maxPeersPerHash {
		return
	}
	ps[p] = time.Now().Add(peerTTL)
}

// query sends a query to addr and waits for the reply. A valid reply adds the
// responder to the routing table; a timeout counts against id, if known.
func (n *Node) query(ctx context.Context, to net.Addr, id *ID, method string, args map[string]any) (map[string]any, error) {
	args["id"] = string(n.id[:])
	c := &call{addr: to.String(), done: make(chan *message, 1)}
	var tid string
	n.mu.Lock()
	for {
		var b [4]byte
		rand.Read(b[:])
		tid = string(b[:])
		if _, used := n.pending[tid]; !used {
			break
		}
	}
	n.pending[tid] = c
	n.mu.Unlock()

	n.send(encodeQuery(tid, method, args), to)
	timer := time.NewTimer(n.timeout)
	defer timer.Stop()
	var m *message
	select {
	case m = <-c.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	if m == nil {
		n.mu.Lock()
		delete(n.pending, tid)
		if id != nil {
			n.table.failed(*id)
		}
		n.mu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n.log.Debug("dht query timed out", "method", method, "to", to)
		return nil, ErrTimeout
	}
	if m.Y == "e" {
		n.log.Debug("dht query error", "method", method, "to", to, "code", m.Code, "msg", m.Msg)
		return nil, fmt.Errorf("dht: %s error %d: %.64q", method, m.Code, m.Msg)
	}
	rid, ok := id20(m.R, "id")
	if !ok {
		return nil, fmt.Errorf("%w: response without id", ErrMalformed)
	}
	if id != nil && rid != *id {
		return nil, fmt.Errorf("%w: node changed ID", ErrMalformed)
	}
	if addr, err := netip.ParseAddrPort(to.String()); err == nil {
		n.mu.Lock()
		n.table.seen(Contact{ID: rid, Addr: netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}, time.Now())
		n.mu.Unlock()
	}
	return m.R, nil
}

func (n *Node) resolve(ctx context.Context, a netip.AddrPort) (net.Addr, error) {
	return n.tr.ResolveAddr(ctx, a.String())
}

// Bootstrap joins the network through the configured bootstrap nodes and then
// looks up our own ID to fill the routing table.
func (n *Node) Bootstrap(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, b := range n.boot {
		wg.Go(func() {
			to, err := n.tr.ResolveAddr(ctx, b)
			if err != nil {
				n.log.Debug("dht bootstrap resolve failed", "addr", b, "err", err)
				return
			}
			n.query(ctx, to, nil, "find_node", map[string]any{"target": string(n.id[:])})
		})
	}
	wg.Wait()
	if n.NumNodes() == 0 {
		return ErrNoNodes
	}
	// Look up our own ID to fill nearby buckets, then random IDs until the table
	// has a useful spread of nodes.
	n.lookup(ctx, n.id, false)
	for range 3 {
		if n.NumNodes() >= 4*K || ctx.Err() != nil {
			break
		}
		n.lookup(ctx, RandomID(), false)
	}
	return nil
}

// AddNode pings addr and adds it to the routing table if it answers.
func (n *Node) AddNode(ctx context.Context, addr string) error {
	to, err := n.tr.ResolveAddr(ctx, addr)
	if err != nil {
		return err
	}
	_, err = n.query(ctx, to, nil, "ping", map[string]any{})
	return err
}

// GetPeers looks up peers for an info-hash.
func (n *Node) GetPeers(ctx context.Context, infoHash [20]byte) ([]netip.AddrPort, error) {
	res, err := n.lookup(ctx, ID(infoHash), true)
	if err != nil {
		return nil, err
	}
	return res.peers, nil
}

// Announce looks up an info-hash, tells the closest nodes we have it on port, and
// returns the peers found on the way.
func (n *Node) Announce(ctx context.Context, infoHash [20]byte, port uint16) ([]netip.AddrPort, error) {
	res, err := n.lookup(ctx, ID(infoHash), true)
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	announced := 0
	for _, c := range res.closest {
		if c.token == "" {
			continue
		}
		announced++
		wg.Go(func() {
			to, err := n.resolve(ctx, c.Addr)
			if err != nil {
				return
			}
			n.query(ctx, to, &c.ID, "announce_peer", map[string]any{
				"info_hash": string(infoHash[:]), "port": int(port), "token": c.token,
			})
		})
	}
	wg.Wait()
	if announced == 0 {
		return res.peers, fmt.Errorf("dht: no node gave us an announce token")
	}
	return res.peers, nil
}
