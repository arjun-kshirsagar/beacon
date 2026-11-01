package tracker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	// MaxResponseSize bounds how much of a tracker response is read.
	MaxResponseSize = 1 << 20
	// DefaultInterval is used when a tracker omits or garbles its interval.
	DefaultInterval = 30 * time.Minute
	maxInterval     = 24 * time.Hour
)

var (
	// ErrFailure reports a tracker's "failure reason".
	ErrFailure = errors.New("tracker: announce failed")
	// ErrBadResponse reports an unparseable tracker response.
	ErrBadResponse = errors.New("tracker: bad response")
	// ErrUnsupported reports an announce URL scheme this package cannot use.
	ErrUnsupported = errors.New("tracker: unsupported scheme")
)

// Event is the optional announce event.
type Event string

const (
	EventNone      Event = ""
	EventStarted   Event = "started"
	EventStopped   Event = "stopped"
	EventCompleted Event = "completed"
)

// Request is an announce request.
type Request struct {
	InfoHash   [20]byte
	PeerID     [20]byte
	Port       uint16
	Uploaded   int64
	Downloaded int64
	Left       int64
	Event      Event
	NumWant    int // zero lets the tracker decide
}

// Response is a parsed announce response.
type Response struct {
	Interval time.Duration
	Peers    []netip.AddrPort
}

// NewHTTPClient returns an HTTP client whose connections go through t.
func NewHTTPClient(t transport.Transport) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return t.Dial(ctx, addr)
			},
		},
	}
}

// Announce sends req to the HTTP tracker at announceURL.
func Announce(ctx context.Context, client *http.Client, announceURL string, req Request) (*Response, error) {
	u, err := url.Parse(announceURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, u.Scheme)
	}

	// info_hash and peer_id are raw bytes, so build the query by hand: url.Values
	// would re-encode them but is fine for the rest.
	q := url.Values{}
	q.Set("port", strconv.Itoa(int(req.Port)))
	q.Set("uploaded", strconv.FormatInt(req.Uploaded, 10))
	q.Set("downloaded", strconv.FormatInt(req.Downloaded, 10))
	q.Set("left", strconv.FormatInt(req.Left, 10))
	q.Set("compact", "1")
	if req.Event != EventNone {
		q.Set("event", string(req.Event))
	}
	if req.NumWant > 0 {
		q.Set("numwant", strconv.Itoa(req.NumWant))
	}
	raw := "info_hash=" + url.QueryEscape(string(req.InfoHash[:])) +
		"&peer_id=" + url.QueryEscape(string(req.PeerID[:])) + "&" + q.Encode()
	if u.RawQuery != "" {
		raw = u.RawQuery + "&" + raw
	}
	u.RawQuery = raw

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("tracker: reading response: %w", err)
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrBadResponse, MaxResponseSize)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d", ErrBadResponse, resp.StatusCode)
	}
	return ParseResponse(body)
}

// ParseResponse parses a bencoded announce response.
func ParseResponse(body []byte) (*Response, error) {
	v, err := bencode.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadResponse, err)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not a dictionary", ErrBadResponse)
	}
	if reason, ok := d["failure reason"].(string); ok {
		return nil, fmt.Errorf("%w: %q", ErrFailure, reason)
	}

	r := &Response{Interval: DefaultInterval}
	if secs, ok := d["interval"].(int64); ok && secs > 0 {
		r.Interval = maxInterval
		if secs < int64(maxInterval/time.Second) {
			r.Interval = time.Duration(secs) * time.Second
		}
	}

	switch peers := d["peers"].(type) {
	case string:
		if len(peers)%6 != 0 {
			return nil, fmt.Errorf("%w: compact peers length %d", ErrBadResponse, len(peers))
		}
		for i := 0; i < len(peers); i += 6 {
			addr := netip.AddrFrom4([4]byte([]byte(peers[i : i+4])))
			r.addPeer(addr, binary.BigEndian.Uint16([]byte(peers[i+4:i+6])))
		}
	case []any:
		for _, p := range peers {
			pd, ok := p.(map[string]any)
			if !ok {
				continue
			}
			ip, _ := pd["ip"].(string)
			port, _ := pd["port"].(int64)
			addr, err := netip.ParseAddr(ip)
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			r.addPeer(addr.Unmap(), uint16(port))
		}
	case nil:
	default:
		return nil, fmt.Errorf("%w: peers has type %T", ErrBadResponse, peers)
	}

	if peers6, ok := d["peers6"].(string); ok {
		if len(peers6)%18 != 0 {
			return nil, fmt.Errorf("%w: compact peers6 length %d", ErrBadResponse, len(peers6))
		}
		for i := 0; i < len(peers6); i += 18 {
			addr := netip.AddrFrom16([16]byte([]byte(peers6[i : i+16])))
			r.addPeer(addr, binary.BigEndian.Uint16([]byte(peers6[i+16:i+18])))
		}
	}
	return r, nil
}

func (r *Response) addPeer(addr netip.Addr, port uint16) {
	if port == 0 || !addr.IsValid() || addr.IsUnspecified() {
		return
	}
	r.Peers = append(r.Peers, netip.AddrPortFrom(addr, port))
}
