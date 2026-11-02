// Package lpd implements BitTorrent Local Service Discovery (BEP 14): peers on
// the same network announce the info-hashes they have over IPv4 multicast.
//
// Anyone on the LAN can send announcements, so they are treated like any other
// peer list: messages are size-capped, strictly parsed, rate-limited per sender,
// and only ever lead to a connection attempt that must still pass the info-hash
// handshake and piece hash checks.
package lpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	// Group4 is the IPv4 multicast group and port BEP 14 uses.
	Group4 = "239.192.152.143:6771"

	maxMessage     = 1400 // fits one Ethernet frame
	maxHashes      = 32   // info-hashes accepted from one message
	hashesPerSend  = 20   // info-hashes we put in one message
	maxLines       = 64
	maxCookie      = 64
	rateWindow     = time.Minute
	maxPerSource   = 20 // messages accepted per sender per window
	maxSources     = 1024
	requestLine    = "BT-SEARCH * HTTP/1.1"
	minAnnounceGap = time.Minute // BEP 14 asks for at most one announce a minute
)

// ErrMalformed reports an announcement that does not follow BEP 14.
var ErrMalformed = errors.New("lpd: malformed announcement")

// Announcement is one BT-SEARCH message.
type Announcement struct {
	Port       uint16
	InfoHashes [][20]byte
	Cookie     string // lets a sender recognise its own multicast echo
}

// Encode returns the message as sent to host (the group address).
func (a Announcement) Encode(host string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\r\nHost: %s\r\nPort: %d\r\n", requestLine, host, a.Port)
	for _, h := range a.InfoHashes {
		fmt.Fprintf(&b, "Infohash: %s\r\n", hex.EncodeToString(h[:]))
	}
	if a.Cookie != "" {
		fmt.Fprintf(&b, "cookie: %s\r\n", a.Cookie)
	}
	b.WriteString("\r\n\r\n")
	return b.Bytes()
}

// Parse parses a BT-SEARCH message. Header names are case-insensitive; invalid
// info-hashes are skipped, but a message needs a valid port and at least one
// valid info-hash.
func Parse(msg []byte) (Announcement, error) {
	var a Announcement
	if len(msg) > maxMessage {
		return a, fmt.Errorf("%w: %d bytes", ErrMalformed, len(msg))
	}
	sc := bufio.NewScanner(bytes.NewReader(msg))
	sc.Buffer(make([]byte, 0, maxMessage), maxMessage)
	if !sc.Scan() || strings.TrimRight(sc.Text(), "\r") != requestLine {
		return a, fmt.Errorf("%w: bad request line", ErrMalformed)
	}
	gotPort := false
	for lines := 0; sc.Scan(); lines++ {
		if lines == maxLines {
			return a, fmt.Errorf("%w: too many headers", ErrMalformed)
		}
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return a, fmt.Errorf("%w: header without colon", ErrMalformed)
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "port":
			if value == "" || strings.Trim(value, "0123456789") != "" {
				return a, fmt.Errorf("%w: bad port", ErrMalformed)
			}
			p, err := strconv.ParseUint(value, 10, 16)
			if err != nil || p == 0 {
				return a, fmt.Errorf("%w: bad port", ErrMalformed)
			}
			a.Port, gotPort = uint16(p), true
		case "infohash":
			var h [20]byte
			if len(value) == 40 && len(a.InfoHashes) < maxHashes {
				if _, err := hex.Decode(h[:], []byte(value)); err == nil {
					a.InfoHashes = append(a.InfoHashes, h)
				}
			}
		case "cookie":
			if len(value) <= maxCookie {
				a.Cookie = value
			}
		}
	}
	if !gotPort || len(a.InfoHashes) == 0 {
		return a, fmt.Errorf("%w: missing port or info-hash", ErrMalformed)
	}
	return a, nil
}

// Config configures a Service.
type Config struct {
	Transport transport.MulticastTransport
	Group     string // zero means Group4
	Logger    *slog.Logger
}

// Service sends and receives announcements on one multicast group.
type Service struct {
	conn   net.PacketConn
	group  net.Addr
	host   string
	cookie string
	log    *slog.Logger

	mu       sync.Mutex
	lastSent map[[20]byte]time.Time
	sources  map[netip.Addr]*window
}

type window struct {
	start time.Time
	count int
}

// New joins the group. Call Run to receive announcements.
func New(cfg Config) (*Service, error) {
	if cfg.Transport == nil {
		return nil, errors.New("lpd: no transport configured")
	}
	if cfg.Group == "" {
		cfg.Group = Group4
	}
	group, err := cfg.Transport.ResolveAddr(context.Background(), cfg.Group)
	if err != nil {
		return nil, err
	}
	conn, err := cfg.Transport.ListenMulticast(cfg.Group)
	if err != nil {
		return nil, err
	}
	var c [8]byte
	rand.Read(c[:])
	s := &Service{
		conn:     conn,
		group:    group,
		host:     cfg.Group,
		cookie:   hex.EncodeToString(c[:]),
		log:      cfg.Logger,
		lastSent: make(map[[20]byte]time.Time),
		sources:  make(map[netip.Addr]*window),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// Announce tells the LAN we serve infoHashes on port. Hashes announced within
// the last minute are skipped, so callers may call it as often as they like.
func (s *Service) Announce(port uint16, infoHashes ...[20]byte) error {
	var due [][20]byte
	s.mu.Lock()
	for _, h := range infoHashes {
		if time.Since(s.lastSent[h]) >= minAnnounceGap {
			due = append(due, h)
		}
	}
	s.mu.Unlock()
	for len(due) > 0 {
		n := min(len(due), hashesPerSend)
		msg := Announcement{Port: port, InfoHashes: due[:n], Cookie: s.cookie}.Encode(s.host)
		if _, err := s.conn.WriteTo(msg, s.group); err != nil {
			// Not recorded as sent, so the next call retries; macOS can refuse
			// the first multicast send right after joining.
			return fmt.Errorf("lpd: %w", err)
		}
		now := time.Now()
		s.mu.Lock()
		for _, h := range due[:n] {
			s.lastSent[h] = now
		}
		s.mu.Unlock()
		due = due[n:]
	}
	return nil
}

// Run receives announcements until ctx is done and reports each announced peer
// to found. It closes the socket on return.
func (s *Service) Run(ctx context.Context, found func(infoHash [20]byte, peer netip.AddrPort)) error {
	defer s.conn.Close()
	defer context.AfterFunc(ctx, func() { s.conn.Close() })()
	buf := make([]byte, maxMessage+1)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		src, err := netip.ParseAddrPort(from.String())
		if err != nil {
			continue
		}
		ip := src.Addr().Unmap()
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || !s.allow(ip) {
			continue
		}
		a, err := Parse(buf[:n])
		if err != nil {
			s.log.Debug("ignoring LPD message", "from", ip, "err", err)
			continue
		}
		if a.Cookie == s.cookie {
			continue // our own announcement, looped back
		}
		peer := netip.AddrPortFrom(ip, a.Port)
		for _, h := range a.InfoHashes {
			found(h, peer)
		}
	}
}

// allow enforces the per-sender rate limit.
func (s *Service) allow(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	w := s.sources[ip]
	if w == nil || now.Sub(w.start) >= rateWindow {
		if w == nil && len(s.sources) >= maxSources {
			clear(s.sources) // a flood of senders; start over rather than grow
		}
		w = &window{start: now}
		s.sources[ip] = w
	}
	w.count++
	return w.count <= maxPerSource
}
