package offline

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// fakeMesh delivers data and shares between services in process, as the BLE
// mesh would.
type fakeMesh struct {
	mu    sync.Mutex
	nodes map[mesh.Fingerprint]*device
}

type device struct {
	name string
	fp   mesh.Fingerprint
	ip   string
	svc  *Service
	net  *fakeMesh
	// groups joined, by network name, for the test to inspect
	joined atomic.Value
}

func (d *device) SendDirectData(to mesh.Fingerprint, data []byte) error {
	d.net.mu.Lock()
	target := d.net.nodes[to]
	d.net.mu.Unlock()
	if target == nil {
		return mesh.ErrUnknownPeer
	}
	go target.svc.OnData(d.fp, append([]byte(nil), data...))
	return nil
}

func (d *device) SendShare(ih [20]byte, name string, size int64) error {
	d.net.mu.Lock()
	defer d.net.mu.Unlock()
	for _, n := range d.net.nodes {
		if n != d {
			sh := mesh.Share{From: d.fp, Nickname: d.name, InfoHash: ih, Name: name, Size: size, Time: time.Now()}
			go n.svc.OnShare(sh)
		}
	}
	return nil
}

// The fake radio: hosting or joining succeeds at once, and every device is
// on 10.0.0.0/24, as if all were in one Wi-Fi Direct group.
func (d *device) Host(network, passphrase string) {
	d.joined.Store(network)
	d.svc.GroupReady(d.ip)
}

func (d *device) Join(network, passphrase string) {
	d.joined.Store(network)
	d.svc.GroupReady(d.ip)
}

func newDevice(t *testing.T, fm *fakeMesh, mem *transport.Memory, name, ip string) *device {
	d := &device{name: name, fp: mesh.Fingerprint(name + "-fingerprint"), ip: ip, net: fm}
	port := atomic.Int32{}
	port.Store(7000)
	d.svc = New(Config{Mesh: d, Groups: d, Dial: mem.From(ip), Dir: t.TempDir(),
		Listen: func() (net.Listener, error) {
			return mem.From(ip).Listen(fmt.Sprintf("%s:%d", ip, port.Add(1)))
		}})
	t.Cleanup(d.svc.Close)
	fm.mu.Lock()
	fm.nodes[d.fp] = d
	fm.mu.Unlock()
	return d
}

func waitTransfer(t *testing.T, d *device, ih [20]byte, state string) Transfer {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, tr := range d.svc.Transfers() {
			if tr.InfoHash == fmt.Sprintf("%x", ih) {
				if tr.State == state {
					return tr
				}
				if tr.State == "failed" {
					t.Fatalf("%s: transfer failed: %s", d.name, tr.Error)
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: never reached %s: %+v", d.name, state, d.svc.Transfers())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitSeen(t *testing.T, d *device, ih [20]byte, sources int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, s := range d.svc.Seen() {
			if s.InfoHash == fmt.Sprintf("%x", ih) && s.Sources >= sources {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never saw the share from %d sources", d.name, sources)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestThreeDevices is the Phase 7 milestone in process: Alice shares a file,
// Bob fetches it from her, and Carol then fetches from Alice and Bob at once.
func TestThreeDevices(t *testing.T) {
	fm := &fakeMesh{nodes: map[mesh.Fingerprint]*device{}}
	mem := transport.NewMemory()
	alice := newDevice(t, fm, mem, "alice", "10.0.0.1")
	bob := newDevice(t, fm, mem, "bob", "10.0.0.2")
	carol := newDevice(t, fm, mem, "carol", "10.0.0.3")

	dir := t.TempDir()
	data := make([]byte, 8<<20+12345)
	rand.Read(data)
	path := filepath.Join(dir, "holiday.bin")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	ih, err := alice.svc.Share(path)
	if err != nil {
		t.Fatal(err)
	}
	waitTransfer(t, alice, ih, "sharing")

	waitSeen(t, bob, ih, 1)
	if err := bob.svc.Get(ih); err != nil {
		t.Fatal(err)
	}
	waitTransfer(t, bob, ih, "seeding")
	if alice.joined.Load() == nil || bob.joined.Load() != alice.joined.Load() {
		t.Fatal("alice did not host a group for bob, or bob joined another")
	}

	// Bob announced the file once he had it; Carol hears from both.
	waitSeen(t, carol, ih, 2)
	if err := carol.svc.Get(ih); err != nil {
		t.Fatal(err)
	}
	tr := waitTransfer(t, carol, ih, "seeding")
	if tr.From["10.0.0.1"] == 0 || tr.From["10.0.0.2"] == 0 {
		t.Fatalf("carol's pieces came from %v; want both alice and bob", tr.From)
	}
	if tr.From["10.0.0.1"]+tr.From["10.0.0.2"] != int64(len(data)) {
		t.Fatalf("credited %v for %d bytes", tr.From, len(data))
	}
	got, err := os.ReadFile(tr.Path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("carol's copy differs")
	}
}

func TestOffersOnlyFromWhoWasAsked(t *testing.T) {
	fm := &fakeMesh{nodes: map[mesh.Fingerprint]*device{}}
	mem := transport.NewMemory()
	bob := newDevice(t, fm, mem, "bob", "10.0.0.2")
	ih := [20]byte{7}
	bob.svc.OnShare(mesh.Share{From: "alice", Nickname: "alice", InfoHash: ih, Name: "x", Size: 10, Time: time.Now()})
	if err := bob.svc.Get(ih); err != nil {
		t.Fatal(err)
	}
	// Mallory, who was not asked, offers her own group.
	o := offer{infoHash: ih, network: "DIRECT-xx-evil", passphrase: "password1",
		peers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.66:7001")}}
	bob.svc.OnData("mallory", o.encode())
	time.Sleep(20 * time.Millisecond)
	if bob.joined.Load() != nil {
		t.Fatal("joined a group offered by someone not asked")
	}
	if tr := bob.svc.Transfers(); len(tr) != 1 || tr[0].State != "asking" {
		t.Fatalf("transfers %+v", tr)
	}
	// Requests for files we do not have are ignored, and no group is hosted.
	bob.svc.OnData("mallory", request{infoHash: [20]byte{9}}.encode())
	time.Sleep(20 * time.Millisecond)
	if bob.joined.Load() != nil {
		t.Fatal("hosted a group for a file we do not have")
	}
}

func TestMessages(t *testing.T) {
	ih := [20]byte{1, 2, 3}
	o := offer{infoHash: ih, network: "DIRECT-bc-abcdef", passphrase: "0123456789abcdef",
		peers: []netip.AddrPort{netip.MustParseAddrPort("192.168.49.1:6881"), netip.MustParseAddrPort("192.168.49.20:51413")}}
	r, got, err := parseMessage(o.encode())
	if err != nil || r != nil || got.network != o.network || got.passphrase != o.passphrase || len(got.peers) != 2 ||
		got.peers[1] != o.peers[1] {
		t.Fatalf("offer round trip: %+v %v", got, err)
	}
	r, got, err = parseMessage(request{infoHash: ih}.encode())
	if err != nil || got != nil || r.infoHash != ih {
		t.Fatal("request round trip")
	}
	bad := func(mod func(*offer)) []byte {
		c := o
		c.peers = append([]netip.AddrPort(nil), o.peers...)
		mod(&c)
		return c.encode()
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"unknown type":  append([]byte{9}, ih[:]...),
		"long request":  append(request{infoHash: ih}.encode(), 0),
		"not DIRECT":    bad(func(c *offer) { c.network = "HomeWifi" }),
		"short pass":    bad(func(c *offer) { c.passphrase = "short" }),
		"space in pass": bad(func(c *offer) { c.passphrase = "has a space" }),
		"public peer":   bad(func(c *offer) { c.peers[0] = netip.MustParseAddrPort("8.8.8.8:53") }),
		"port zero":     bad(func(c *offer) { c.peers[0] = netip.MustParseAddrPort("192.168.49.1:0") }),
		"no peers":      bad(func(c *offer) { c.peers = nil }),
		"truncated":     o.encode()[:30],
	} {
		if _, _, err := parseMessage(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !sameSubnet(netip.MustParseAddr("192.168.49.1"), netip.MustParseAddr("192.168.49.200")) ||
		sameSubnet(netip.MustParseAddr("192.168.49.1"), netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("subnet check")
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(request{infoHash: [20]byte{1}}.encode())
	f.Add(offer{infoHash: [20]byte{1}, network: "DIRECT-bc-abcdef", passphrase: "0123456789abcdef",
		peers: []netip.AddrPort{netip.MustParseAddrPort("192.168.49.1:6881")}}.encode())
	f.Fuzz(func(t *testing.T, data []byte) {
		r, o, err := parseMessage(data)
		switch {
		case err != nil:
		case r != nil:
			if !bytes.Equal(r.encode(), data) {
				t.Fatal("request did not round-trip")
			}
		case o != nil:
			if !bytes.Equal(o.encode(), data) {
				t.Fatal("offer did not round-trip")
			}
			if len(o.peers) > maxOfferPeers {
				t.Fatal("too many peers")
			}
		}
	})
}
