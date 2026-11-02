package tracker

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// fakeUDPTracker answers BEP 15 connect and announce requests. It drops the
// first dropFirst packets and, before each real reply, sends a forged reply from
// another address.
func fakeUDPTracker(t *testing.T, m *transport.Memory, addr string, dropFirst int, reply func(req []byte) []byte) {
	t.Helper()
	conn, err := m.ListenPacket(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	forger, _ := m.ListenPacket("")
	t.Cleanup(func() { forger.Close() })

	go func() {
		buf := make([]byte, 2048)
		const connID = 0x1122334455667788
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if dropFirst > 0 {
				dropFirst--
				continue
			}
			p := buf[:n]
			action := binary.BigEndian.Uint32(p[8:12])
			tid := p[12:16]
			var out []byte
			switch {
			case action == actionConnect && binary.BigEndian.Uint64(p[0:8]) == udpProtocolID:
				out = binary.BigEndian.AppendUint32(nil, actionConnect)
				out = append(out, tid...)
				out = binary.BigEndian.AppendUint64(out, connID)
			case action == actionAnnounce && binary.BigEndian.Uint64(p[0:8]) == connID && n == 98:
				out = binary.BigEndian.AppendUint32(nil, actionAnnounce)
				out = append(out, tid...)
				out = append(out, reply(p)...)
			default:
				out = binary.BigEndian.AppendUint32(nil, actionError)
				out = append(out, tid...)
				out = append(out, "bad request"...)
			}
			forged := append([]byte(nil), out...)
			forged = append(forged[:8], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"...)
			forger.WriteTo(forged, from)
			conn.WriteTo(out, from)
		}
	}()
}

func TestAnnounceUDP(t *testing.T) {
	defer func(d time.Duration) { UDPTimeout = d }(UDPTimeout)
	UDPTimeout = 50 * time.Millisecond

	m := transport.NewMemory()
	req := Request{Port: 6881, Left: 1000, Event: EventStarted}
	copy(req.InfoHash[:], "info-hash-0123456789")
	copy(req.PeerID[:], "-BC0001-abcdefghijkl")

	fakeUDPTracker(t, m, "tracker:1337", 1, func(p []byte) []byte {
		if string(p[16:36]) != string(req.InfoHash[:]) || string(p[36:56]) != string(req.PeerID[:]) ||
			binary.BigEndian.Uint64(p[64:72]) != 1000 || binary.BigEndian.Uint32(p[80:84]) != 2 ||
			binary.BigEndian.Uint16(p[96:98]) != 6881 {
			return []byte("garbage")
		}
		out := binary.BigEndian.AppendUint32(nil, 600) // interval
		out = binary.BigEndian.AppendUint32(out, 1)    // leechers
		out = binary.BigEndian.AppendUint32(out, 2)    // seeders
		return append(out, 10, 0, 0, 1, 0x1a, 0xe1, 10, 0, 0, 2, 0, 0)
	})

	c := NewClient(m, m)
	resp, err := c.Announce(context.Background(), "udp://tracker:1337/announce", req)
	if err != nil {
		t.Fatal(err)
	}
	want := &Response{Interval: 10 * time.Minute, Peers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:6881")}}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("got %+v, want %+v", resp, want)
	}
}

func TestAnnounceUDPErrors(t *testing.T) {
	defer func(d time.Duration) { UDPTimeout = d }(UDPTimeout)
	UDPTimeout = 20 * time.Millisecond
	m := transport.NewMemory()

	fakeUDPTracker(t, m, "short:1", 0, func([]byte) []byte { return []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1} })
	if _, err := AnnounceUDP(context.Background(), m, "udp://short:1", Request{}); !errors.Is(err, ErrBadResponse) {
		t.Errorf("odd peer list: got %v", err)
	}
	if _, err := AnnounceUDP(context.Background(), m, "udp://nobody:1", Request{}); err == nil {
		t.Error("silent tracker: no error")
	}
	if _, err := AnnounceUDP(context.Background(), m, "http://x/announce", Request{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("http URL: got %v", err)
	}
	if _, err := (&Client{}).Announce(context.Background(), "udp://x:1", Request{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("client without UDP: got %v", err)
	}

	// A tracker error reply surfaces as ErrFailure.
	conn, _ := m.ListenPacket("errs:1")
	defer conn.Close()
	go func() {
		buf := make([]byte, 128)
		n, from, err := conn.ReadFrom(buf)
		if err != nil || n < 16 {
			return
		}
		out := binary.BigEndian.AppendUint32(nil, actionError)
		conn.WriteTo(append(append(out, buf[12:16]...), "torrent not registered"...), from)
	}()
	if _, err := AnnounceUDP(context.Background(), m, "udp://errs:1", Request{}); !errors.Is(err, ErrFailure) {
		t.Errorf("error reply: got %v", err)
	}
	var _ net.PacketConn = conn
}

func FuzzParseUDPAnnounce(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\x01tidx\x00\x00\x02\x58\x00\x00\x00\x01\x00\x00\x00\x02\x0a\x00\x00\x01\x1a\xe1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseUDPAnnounce(b)
		if err != nil {
			return
		}
		if r.Interval <= 0 || r.Interval > maxInterval || len(r.Peers) > (len(b)-20)/6 {
			t.Fatalf("bad response %+v", r)
		}
	})
}
