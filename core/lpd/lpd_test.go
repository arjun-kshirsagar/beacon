package lpd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func TestEncodeParse(t *testing.T) {
	a := Announcement{Port: 6881, InfoHashes: [][20]byte{{1}, {0xab, 0xcd}}, Cookie: "c00kie"}
	msg := a.Encode(Group4)
	if !strings.HasPrefix(string(msg), "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\n") {
		t.Fatalf("encoded %q", msg)
	}
	got, err := Parse(msg)
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestParseVariants(t *testing.T) {
	// Other clients vary header case and line endings.
	msg := "BT-SEARCH * HTTP/1.1\nHOST: 239.192.152.143:6771\nport:51413\ninfohash: " +
		strings.Repeat("AB", 20) + "\nInfohash: nothex\nX-Other: 1\n\n"
	a, err := Parse([]byte(msg))
	if err != nil || a.Port != 51413 || len(a.InfoHashes) != 1 || a.InfoHashes[0][0] != 0xab {
		t.Fatalf("got %+v, %v", a, err)
	}

	hash := "Infohash: " + strings.Repeat("00", 20) + "\r\n"
	bad := map[string]string{
		"wrong method":    "GET / HTTP/1.1\r\nPort: 1\r\n" + hash,
		"no port":         "BT-SEARCH * HTTP/1.1\r\n" + hash,
		"port zero":       "BT-SEARCH * HTTP/1.1\r\nPort: 0\r\n" + hash,
		"port too big":    "BT-SEARCH * HTTP/1.1\r\nPort: 70000\r\n" + hash,
		"signed port":     "BT-SEARCH * HTTP/1.1\r\nPort: +80\r\n" + hash,
		"no hash":         "BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n\r\n",
		"header no colon": "BT-SEARCH * HTTP/1.1\r\nPort 1\r\n" + hash,
		"oversized":       "BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n" + strings.Repeat(hash, 30),
		"too many lines":  "BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n" + strings.Repeat("X: y\r\n", maxLines+1) + hash,
	}
	for name, m := range bad {
		if _, err := Parse([]byte(m)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

type found struct {
	hash [20]byte
	peer netip.AddrPort
}

func start(t *testing.T, mt transport.MulticastTransport) (*Service, chan found) {
	t.Helper()
	s, err := New(Config{Transport: mt})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan found, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx, func(h [20]byte, p netip.AddrPort) { ch <- found{h, p} })
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s, ch
}

func TestDiscovery(t *testing.T) {
	m := transport.NewMemory()
	a, aFound := start(t, m.MulticastFrom("192.168.1.10"))
	_, bFound := start(t, m.MulticastFrom("192.168.1.20"))
	ih := [20]byte{42}

	if err := a.Announce(7000, ih); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-bFound:
		if f.hash != ih || f.peer != netip.MustParseAddrPort("192.168.1.10:7000") {
			t.Fatalf("got %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("announcement not received")
	}
	// The sender ignores its own echo, and a repeat within a minute is not sent.
	a.Announce(7000, ih)
	select {
	case f := <-aFound:
		t.Fatalf("sender heard itself: %+v", f)
	case f := <-bFound:
		t.Fatalf("repeat announce sent: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRateLimit(t *testing.T) {
	m := transport.NewMemory()
	_, found := start(t, m.MulticastFrom("192.168.1.20"))
	flood, err := m.MulticastFrom("192.168.1.66").ListenMulticast(Group4)
	if err != nil {
		t.Fatal(err)
	}
	defer flood.Close()
	group, _ := m.ResolveAddr(context.Background(), Group4)
	for i := range 3 * maxPerSource {
		msg := Announcement{Port: uint16(1000 + i), InfoHashes: [][20]byte{{byte(i)}}}.Encode(Group4)
		flood.WriteTo(msg, group)
	}
	got := 0
	for {
		select {
		case <-found:
			got++
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if got != maxPerSource {
		t.Fatalf("accepted %d messages from one sender, want %d", got, maxPerSource)
	}
}

func TestAnnounceSplitsLargeSets(t *testing.T) {
	m := transport.NewMemory()
	a, _ := start(t, m.MulticastFrom("192.168.1.10"))
	_, found := start(t, m.MulticastFrom("192.168.1.20"))
	var hashes [][20]byte
	for i := range 45 {
		hashes = append(hashes, [20]byte{byte(i), 1})
	}
	a.Announce(7000, hashes...)
	seen := map[[20]byte]bool{}
	for len(seen) < len(hashes) {
		select {
		case f := <-found:
			seen[f.hash] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("got %d of %d hashes", len(seen), len(hashes))
		}
	}
	if msg := (Announcement{Port: 7000, InfoHashes: hashes[:hashesPerSend], Cookie: fmt.Sprint(1e15)}).Encode(Group4); len(msg) > maxMessage {
		t.Fatalf("a full message is %d bytes, over %d", len(msg), maxMessage)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(Announcement{Port: 6881, InfoHashes: [][20]byte{{1}}, Cookie: "x"}.Encode(Group4)))
	f.Add([]byte("BT-SEARCH * HTTP/1.1\nport: 1\ninfohash: " + strings.Repeat("ff", 20) + "\n\n"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		a, err := Parse(msg)
		if err != nil {
			return
		}
		if a.Port == 0 || len(a.InfoHashes) == 0 || len(a.InfoHashes) > maxHashes || len(a.Cookie) > maxCookie {
			t.Fatalf("accepted bad announcement %+v", a)
		}
	})
}

// failingConn refuses the first write, like a multicast send right after joining.
type failingConn struct {
	net.PacketConn
	fails int
}

func (f *failingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if f.fails > 0 {
		f.fails--
		return 0, errors.New("sendto: no route to host")
	}
	return f.PacketConn.WriteTo(b, addr)
}

func TestAnnounceRetriesAfterFailedSend(t *testing.T) {
	m := transport.NewMemory()
	_, found := start(t, m.MulticastFrom("192.168.1.20"))
	a, err := New(Config{Transport: m.MulticastFrom("192.168.1.10")}) // sends only
	if err != nil {
		t.Fatal(err)
	}
	defer a.conn.Close()
	a.conn = &failingConn{PacketConn: a.conn, fails: 1}
	ih := [20]byte{5}
	if err := a.Announce(7000, ih); err == nil {
		t.Fatal("first announce should fail")
	}
	if err := a.Announce(7000, ih); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-found:
		if f.hash != ih {
			t.Fatalf("got %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed send blocked the retry")
	}
}
