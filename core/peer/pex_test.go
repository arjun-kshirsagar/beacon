package peer

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func TestPEXRoundTrip(t *testing.T) {
	p := PEX{
		Added: []netip.AddrPort{
			netip.MustParseAddrPort("10.0.0.1:6881"),
			netip.MustParseAddrPort("[2001:db8::7]:51413"),
			netip.MustParseAddrPort("192.168.1.2:80"),
		},
		Flags:   []byte{PEXSeed | PEXReachable, PEXEncryption, 0},
		Dropped: []netip.AddrPort{netip.MustParseAddrPort("10.9.9.9:1"), netip.MustParseAddrPort("[2001:db8::9]:2")},
	}
	got, err := ParsePEX(p.Encode())
	if err != nil {
		t.Fatal(err)
	}
	// IPv4 entries come first after a round trip; flags stay with their peer.
	want := PEX{
		Added:   []netip.AddrPort{p.Added[0], p.Added[2], p.Added[1]},
		Flags:   []byte{PEXSeed | PEXReachable, 0, PEXEncryption},
		Dropped: p.Dropped,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParsePEXLimits(t *testing.T) {
	var many PEX
	for i := range 3 * MaxPEXPeers {
		many.Added = append(many.Added, netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.%d:6881", i/250, i%250+1)))
		many.Dropped = append(many.Dropped, netip.MustParseAddrPort(fmt.Sprintf("10.1.%d.%d:6881", i/250, i%250+1)))
	}
	got, err := ParsePEX(many.Encode())
	if err != nil || len(got.Added) != MaxPEXPeers || len(got.Dropped) != MaxPEXPeers || len(got.Flags) != MaxPEXPeers {
		t.Fatalf("added %d dropped %d flags %d, %v", len(got.Added), len(got.Dropped), len(got.Flags), err)
	}

	// Unusable addresses are skipped, and their flags with them.
	junk := PEX{
		Added: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:1"), netip.MustParseAddrPort("10.0.0.1:0"),
			netip.MustParseAddrPort("224.0.0.1:5"), netip.MustParseAddrPort("10.0.0.2:5")},
		Flags: []byte{1, 2, 3, PEXSeed},
	}
	got, _ = ParsePEX(junk.Encode())
	if len(got.Added) != 1 || got.Added[0].Port() != 5 || got.Flags[0] != PEXSeed {
		t.Fatalf("got %+v", got)
	}

	for _, body := range []string{"le", "d5:added5:abcdee", "d6:added617:xxxxxxxxxxxxxxxxxe"} {
		if _, err := ParsePEX([]byte(body)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: got %v", body, err)
		}
	}
}

func FuzzParsePEX(f *testing.F) {
	f.Add(PEX{Added: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:6881")}, Flags: []byte{PEXSeed}}.Encode())
	f.Add([]byte("d5:added6:\x0a\x00\x00\x01\x1a\xe17:added.f1:\x02e"))
	f.Fuzz(func(t *testing.T, body []byte) {
		p, err := ParsePEX(body)
		if err != nil {
			return
		}
		if len(p.Added) > MaxPEXPeers || len(p.Dropped) > MaxPEXPeers || len(p.Flags) != len(p.Added) {
			t.Fatalf("unbounded or misaligned: %d added, %d flags, %d dropped", len(p.Added), len(p.Flags), len(p.Dropped))
		}
		for _, a := range p.Added {
			if a.Port() == 0 || a.Addr().IsUnspecified() {
				t.Fatalf("accepted %v", a)
			}
		}
	})
}
