package tracker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	udpProtocolID  = 0x41727101980
	actionConnect  = 0
	actionAnnounce = 1
	actionError    = 3
	udpPacketMax   = 64 << 10
)

// UDPTimeout and UDPRetries control retransmission. BEP 15 suggests 15·2ⁿ
// seconds; shorter waits suit an interactive client.
var (
	UDPTimeout = 3 * time.Second
	UDPRetries = 3
)

// AnnounceUDP sends req to the UDP tracker at announceURL (BEP 15).
func AnnounceUDP(ctx context.Context, pt transport.PacketTransport, announceURL string, req Request) (*Response, error) {
	u, err := url.Parse(announceURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	if u.Scheme != "udp" || u.Host == "" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, announceURL)
	}
	addr, err := pt.ResolveAddr(ctx, u.Host)
	if err != nil {
		return nil, fmt.Errorf("tracker: resolving %s: %w", u.Host, err)
	}
	conn, err := pt.ListenPacket("")
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	s := &udpSession{conn: conn, addr: addr}

	connResp, err := s.roundTrip(ctx, func(tid uint32) []byte {
		b := binary.BigEndian.AppendUint64(nil, udpProtocolID)
		b = binary.BigEndian.AppendUint32(b, actionConnect)
		return binary.BigEndian.AppendUint32(b, tid)
	}, actionConnect, 16)
	if err != nil {
		return nil, err
	}
	connID := binary.BigEndian.Uint64(connResp[8:16])

	var key [4]byte
	rand.Read(key[:])
	resp, err := s.roundTrip(ctx, func(tid uint32) []byte {
		b := binary.BigEndian.AppendUint64(nil, connID)
		b = binary.BigEndian.AppendUint32(b, actionAnnounce)
		b = binary.BigEndian.AppendUint32(b, tid)
		b = append(b, req.InfoHash[:]...)
		b = append(b, req.PeerID[:]...)
		b = binary.BigEndian.AppendUint64(b, uint64(req.Downloaded))
		b = binary.BigEndian.AppendUint64(b, uint64(req.Left))
		b = binary.BigEndian.AppendUint64(b, uint64(req.Uploaded))
		b = binary.BigEndian.AppendUint32(b, udpEvent(req.Event))
		b = binary.BigEndian.AppendUint32(b, 0) // IP: use the sender's
		b = append(b, key[:]...)
		numWant := int32(-1)
		if req.NumWant > 0 {
			numWant = int32(min(req.NumWant, 1<<16))
		}
		b = binary.BigEndian.AppendUint32(b, uint32(numWant))
		return binary.BigEndian.AppendUint16(b, req.Port)
	}, actionAnnounce, 20)
	if err != nil {
		return nil, err
	}
	return parseUDPAnnounce(resp)
}

func udpEvent(e Event) uint32 {
	switch e {
	case EventCompleted:
		return 1
	case EventStarted:
		return 2
	case EventStopped:
		return 3
	}
	return 0
}

// parseUDPAnnounce parses an announce response after its action and
// transaction ID have been checked.
func parseUDPAnnounce(b []byte) (*Response, error) {
	if len(b) < 20 || (len(b)-20)%6 != 0 {
		return nil, fmt.Errorf("%w: UDP announce response is %d bytes", ErrBadResponse, len(b))
	}
	r := &Response{Interval: DefaultInterval}
	if secs := binary.BigEndian.Uint32(b[8:12]); secs > 0 {
		r.Interval = min(time.Duration(secs)*time.Second, maxInterval)
	}
	for p := b[20:]; len(p) >= 6; p = p[6:] {
		r.addPeer(netip.AddrFrom4([4]byte(p[:4])), binary.BigEndian.Uint16(p[4:6]))
	}
	return r, nil
}

type udpSession struct {
	conn net.PacketConn
	addr net.Addr
}

// roundTrip sends the packet build makes for a fresh transaction ID and waits
// for a matching reply of at least minLen bytes, retransmitting on timeout.
// Replies from other addresses or for other transactions are ignored.
func (s *udpSession) roundTrip(ctx context.Context, build func(tid uint32) []byte, action uint32, minLen int) ([]byte, error) {
	buf := make([]byte, udpPacketMax)
	for range UDPRetries {
		var tidBuf [4]byte
		rand.Read(tidBuf[:])
		tid := binary.BigEndian.Uint32(tidBuf[:])
		if _, err := s.conn.WriteTo(build(tid), s.addr); err != nil {
			return nil, fmt.Errorf("tracker: %w", err)
		}
		s.conn.SetReadDeadline(time.Now().Add(UDPTimeout))
		for {
			n, from, err := s.conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break // retransmit
				}
				return nil, fmt.Errorf("tracker: %w", err)
			}
			p := buf[:n]
			if from.String() != s.addr.String() || n < 8 || binary.BigEndian.Uint32(p[4:8]) != tid {
				continue
			}
			switch binary.BigEndian.Uint32(p[0:4]) {
			case actionError:
				return nil, fmt.Errorf("%w: %q", ErrFailure, p[8:])
			case action:
				if n < minLen {
					return nil, fmt.Errorf("%w: %d-byte reply", ErrBadResponse, n)
				}
				return append([]byte(nil), p...), nil
			default:
				return nil, fmt.Errorf("%w: unexpected action", ErrBadResponse)
			}
		}
	}
	return nil, fmt.Errorf("tracker: %s did not answer", s.addr)
}
