// Package lan links Beacon mesh nodes on the same local network: nodes find
// each other with UDP multicast beacons and connect over TCP, each connection
// becoming a mesh link. See docs/protocol-spec.md.
//
// Anyone on the LAN can send beacons and connect, so beacons are rate-limited
// per sender, a beacon can only lead to a connection to the address it came
// from, connections are capped, and everything carried over a link is checked
// by the mesh as hostile input.
package lan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	// Group4 is the IPv4 multicast group LAN beacons are sent to.
	Group4 = "239.255.66.66:6766"
	// MTU is the frame size of LAN links: any mesh packet fits in one frame.
	MTU = 8192

	beaconSize     = 4 + 1 + instanceSize + 2
	instanceSize   = 8
	helloSize      = len(helloMagic) + 1 + instanceSize
	helloMagic     = "beacon-link\x00"
	version        = 1
	beaconInterval = 5 * time.Second
	helloTimeout   = 5 * time.Second
	redialAfter    = 10 * time.Second
	beaconsPerMin  = 30 // accepted from one sender
	maxSources     = 1024
	defaultLinks   = 16
	maxPendingIP   = 2 // unfinished handshakes from one IP
)

var beaconMagic = []byte("BCN1")

// Instance identifies one running node for linking purposes only. It is random
// per run and proves nothing; identity is the mesh's business.
type Instance [instanceSize]byte

// ErrMalformed reports a beacon or hello that does not follow the format.
var ErrMalformed = errors.New("lan: malformed message")

// Beacon is the datagram nodes multicast: "BCN1", version, instance, TCP port.
type Beacon struct {
	Instance Instance
	Port     uint16
}

// Encode returns the wire form of b.
func (b Beacon) Encode() []byte {
	out := append(append([]byte(nil), beaconMagic...), version)
	out = append(out, b.Instance[:]...)
	return binary.BigEndian.AppendUint16(out, b.Port)
}

// ParseBeacon decodes a beacon.
func ParseBeacon(data []byte) (Beacon, error) {
	if len(data) != beaconSize || !bytes.HasPrefix(data, beaconMagic) || data[4] != version {
		return Beacon{}, ErrMalformed
	}
	var b Beacon
	copy(b.Instance[:], data[5:])
	b.Port = binary.BigEndian.Uint16(data[5+instanceSize:])
	if b.Port == 0 {
		return Beacon{}, ErrMalformed
	}
	return b, nil
}

// Config configures a Links.
type Config struct {
	// Stream carries links (TCP on a desktop).
	Stream transport.Transport
	// Multicast carries beacons; nil turns discovery off.
	Multicast transport.MulticastTransport
	// Group is the multicast group; default Group4.
	Group string
	// Listen is the address to accept links on, such as ":0".
	Listen string
	// MaxLinks caps live links; default 16.
	MaxLinks int
	Logger   *slog.Logger
}

// Links finds and connects to other nodes on the LAN and hands each connection
// to the mesh as a link. It implements transport.LinkTransport.
type Links struct {
	cfg   Config
	self  Instance
	ln    net.Listener
	port  uint16
	group net.Addr
	mc    net.PacketConn // nil without discovery
	log   *slog.Logger
	ready chan transport.Link

	mu      sync.Mutex
	links   map[Instance]*lanLink
	pending map[string]int // unfinished handshakes per remote IP
	dialed  map[Instance]time.Time
	sources map[netip.Addr]*window
}

type window struct {
	start time.Time
	count int
}

type lanLink struct {
	*transport.StreamLink
	l        *Links
	instance Instance
	dialer   Instance // which side dialed; decides between duplicate links
	once     sync.Once
}

// Close closes the link and forgets it, so the peer can be linked again.
func (k *lanLink) Close() error {
	k.once.Do(func() {
		k.l.mu.Lock()
		if k.l.links[k.instance] == k {
			delete(k.l.links, k.instance)
		}
		k.l.mu.Unlock()
	})
	return k.StreamLink.Close()
}

// Listen starts accepting links and, with a multicast transport, joins the
// beacon group. Call Run to start beaconing and accepting.
func Listen(cfg Config) (*Links, error) {
	if cfg.Stream == nil {
		return nil, errors.New("lan: no stream transport")
	}
	if cfg.Group == "" {
		cfg.Group = Group4
	}
	if cfg.MaxLinks <= 0 {
		cfg.MaxLinks = defaultLinks
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	l := &Links{cfg: cfg, log: cfg.Logger, ready: make(chan transport.Link, 64),
		links: make(map[Instance]*lanLink), pending: make(map[string]int),
		dialed: make(map[Instance]time.Time), sources: make(map[netip.Addr]*window)}
	rand.Read(l.self[:])
	ln, err := cfg.Stream.Listen(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("lan: %w", err)
	}
	l.ln = ln
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err == nil {
		p, _ := strconv.ParseUint(port, 10, 16)
		l.port = uint16(p)
	}
	if cfg.Multicast != nil {
		if l.group, err = cfg.Multicast.ResolveAddr(context.Background(), cfg.Group); err == nil {
			l.mc, err = cfg.Multicast.ListenMulticast(cfg.Group)
		}
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("lan: joining %s: %w", cfg.Group, err)
		}
	}
	return l, nil
}

// Port returns the TCP port links are accepted on.
func (l *Links) Port() uint16 { return l.port }

// Run accepts links and, if discovery is on, sends and answers beacons until
// ctx ends.
func (l *Links) Run(ctx context.Context) {
	defer context.AfterFunc(ctx, func() {
		l.ln.Close()
		if l.mc != nil {
			l.mc.Close()
		}
		l.mu.Lock()
		for _, k := range l.links {
			k.StreamLink.Close()
		}
		l.mu.Unlock()
	})()
	if l.mc != nil {
		go l.beacon(ctx)
		go l.listenBeacons(ctx)
	}
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handshake(ctx, conn, false)
	}
}

// Accept returns the next link.
func (l *Links) Accept(ctx context.Context) (transport.Link, error) {
	select {
	case k := <-l.ready:
		return k, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Dial links to a node at addr, such as one the user named.
func (l *Links) Dial(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	conn, err := l.cfg.Stream.Dial(ctx, addr)
	if err != nil {
		return fmt.Errorf("lan: %w", err)
	}
	return l.handshake(ctx, conn, true)
}

func (l *Links) beacon(ctx context.Context) {
	msg := Beacon{Instance: l.self, Port: l.port}.Encode()
	t := time.NewTicker(beaconInterval)
	defer t.Stop()
	for {
		if _, err := l.mc.WriteTo(msg, l.group); err != nil {
			l.log.Debug("sending beacon", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (l *Links) listenBeacons(ctx context.Context) {
	buf := make([]byte, 64)
	for {
		n, from, err := l.mc.ReadFrom(buf)
		if err != nil {
			return
		}
		src, err := netip.ParseAddrPort(from.String())
		if err != nil {
			continue
		}
		ip := src.Addr().Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || !l.allow(ip) {
			continue
		}
		b, err := ParseBeacon(buf[:n])
		if err != nil || b.Instance == l.self || !l.shouldDial(b.Instance) {
			continue
		}
		// Only ever connect to the address the beacon came from, so a beacon
		// cannot aim us at some other host.
		addr := netip.AddrPortFrom(ip, b.Port).String()
		go func() {
			if err := l.Dial(ctx, addr); err != nil {
				l.log.Debug("linking to discovered node", "addr", addr, "err", err)
			}
		}()
	}
}

// allow enforces the per-sender beacon rate.
func (l *Links) allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.sources[ip]
	if w == nil || now.Sub(w.start) >= time.Minute {
		if w == nil && len(l.sources) >= maxSources {
			clear(l.sources)
		}
		w = &window{start: now}
		l.sources[ip] = w
	}
	w.count++
	return w.count <= beaconsPerMin
}

// shouldDial reports whether a beacon from inst should lead to a dial: not
// while linked, not too soon after the last try, and not past the cap.
func (l *Links) shouldDial(inst Instance) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.links[inst] != nil || len(l.links) >= l.cfg.MaxLinks || time.Since(l.dialed[inst]) < redialAfter {
		return false
	}
	if len(l.dialed) >= maxSources {
		clear(l.dialed)
	}
	l.dialed[inst] = time.Now()
	return true
}

func hello(self Instance) []byte {
	return append(append([]byte(helloMagic), version), self[:]...)
}

func parseHello(b []byte) (Instance, error) {
	var inst Instance
	if len(b) != helloSize || !bytes.HasPrefix(b, []byte(helloMagic)) || b[len(helloMagic)] != version {
		return inst, ErrMalformed
	}
	copy(inst[:], b[len(helloMagic)+1:])
	return inst, nil
}

// handshake exchanges hellos on a new connection and registers the link.
func (l *Links) handshake(ctx context.Context, conn net.Conn, outgoing bool) error {
	host := remoteHost(conn)
	l.mu.Lock()
	if l.pending[host] >= maxPendingIP {
		l.mu.Unlock()
		conn.Close()
		return errors.New("lan: too many handshakes from one address")
	}
	l.pending[host]++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		if l.pending[host]--; l.pending[host] <= 0 {
			delete(l.pending, host)
		}
		l.mu.Unlock()
	}()

	conn.SetDeadline(time.Now().Add(helloTimeout))
	errc := make(chan error, 1)
	go func() { _, err := conn.Write(hello(l.self)); errc <- err }()
	buf := make([]byte, helloSize)
	_, err := io.ReadFull(conn, buf)
	if werr := <-errc; err == nil {
		err = werr
	}
	var peer Instance
	if err == nil {
		peer, err = parseHello(buf)
	}
	if err == nil && peer == l.self {
		err = errors.New("lan: connected to ourselves")
	}
	if err != nil {
		conn.Close()
		return err
	}
	conn.SetDeadline(time.Time{})

	dialer := peer
	if outgoing {
		dialer = l.self
	}
	k := &lanLink{StreamLink: transport.NewStreamLink(conn, MTU, conn.RemoteAddr().String()),
		l: l, instance: peer, dialer: dialer}
	l.mu.Lock()
	old := l.links[peer]
	switch {
	case old == nil && len(l.links) >= l.cfg.MaxLinks:
		l.mu.Unlock()
		conn.Close()
		return errors.New("lan: link limit reached")
	case old != nil && !lowerDialer(k, old):
		// Both sides dialed at once. Each keeps the connection dialed by the
		// lower instance, so they agree on which one survives.
		l.mu.Unlock()
		conn.Close()
		return nil
	}
	l.links[peer] = k
	l.mu.Unlock()
	if old != nil {
		old.StreamLink.Close()
	}
	select {
	case l.ready <- k:
		l.log.Debug("LAN link up", "peer", k.Peer())
		return nil
	case <-ctx.Done():
		k.Close()
		return ctx.Err()
	}
}

func lowerDialer(a, b *lanLink) bool { return bytes.Compare(a.dialer[:], b.dialer[:]) < 0 }

func remoteHost(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
