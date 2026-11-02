package torrent

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseMagnet(t *testing.T) {
	const hexHash = "c56b1130cc07ab836e30149199aede14b00b6855"
	var want [HashSize]byte
	hex.Decode(want[:], []byte(hexHash))

	m, err := ParseMagnet("magnet:?xt=urn:btih:" + hexHash + "&dn=photos&tr=udp%3A%2F%2Ft.example%3A1337&tr=http://a.example/announce&x.pe=10.0.0.1:6881")
	if err != nil {
		t.Fatal(err)
	}
	if m.InfoHash != want || m.Name != "photos" {
		t.Errorf("got %+v", m)
	}
	if !reflect.DeepEqual(m.Trackers, []string{"udp://t.example:1337", "http://a.example/announce"}) {
		t.Errorf("trackers %v", m.Trackers)
	}
	if !reflect.DeepEqual(m.Peers, []string{"10.0.0.1:6881"}) {
		t.Errorf("peers %v", m.Peers)
	}

	// Base32 form of the same hash, and a round trip through String.
	b32, err := ParseMagnet("magnet:?xt=urn:btih:YVVRCMGMA6VYG3RQCSIZTLW6CSYAW2CV")
	if err != nil || b32.InfoHash != want {
		t.Fatalf("base32: %+v, %v", b32, err)
	}
	again, err := ParseMagnet(m.String())
	if err != nil || !reflect.DeepEqual(again, m) {
		t.Fatalf("round trip: %+v, %v", again, err)
	}
}

func TestParseMagnetErrors(t *testing.T) {
	for _, uri := range []string{
		"http://example.com",
		"magnet:?dn=nohash",
		"magnet:?xt=urn:btih:1234",
		"magnet:?xt=urn:btih:zz6b1130cc07ab836e30149199aede14b00b6855",
		"magnet:?xt=urn:btih:" + strings.Repeat("a", 40) + "&tr=" + strings.Repeat("x", maxMagnetLen),
	} {
		if _, err := ParseMagnet(uri); !errors.Is(err, ErrMagnet) {
			t.Errorf("%.60q: got %v", uri, err)
		}
	}
}

func TestFromInfo(t *testing.T) {
	info := map[string]any{"name": "f", "piece length": 4, "pieces": strings.Repeat("a", 20), "length": 4}
	meta := encode(t, map[string]any{"info": info, "announce": "http://x/announce"})
	orig, err := Parse(meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromInfo(orig.InfoBytes, []string{"udp://t:1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.InfoHash != orig.InfoHash || got.Name != "f" || !reflect.DeepEqual(got.Trackers(), []string{"udp://t:1"}) {
		t.Fatalf("got %+v", got)
	}
	if _, err := FromInfo([]byte("i1e"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-dict info: %v", err)
	}
}

func FuzzParseMagnet(f *testing.F) {
	f.Add("magnet:?xt=urn:btih:c56b1130cc07ab836e30149199aede14b00b6855&dn=x&tr=udp://t:1")
	f.Add("magnet:?xt=urn:btih:YVVRCMGMA6VYG3RQCSIZTLW6CSYAW2CV")
	f.Fuzz(func(t *testing.T, uri string) {
		m, err := ParseMagnet(uri)
		if err != nil {
			return
		}
		if len(m.Trackers) > maxMagnetItems || len(m.Peers) > maxMagnetItems {
			t.Fatalf("unbounded lists: %d trackers, %d peers", len(m.Trackers), len(m.Peers))
		}
		// Re-escaping can grow a link past the length limit; only shorter ones must re-parse.
		if s := m.String(); len(s) > maxMagnetLen {
			return
		}
		if _, err := ParseMagnet(m.String()); err != nil {
			t.Fatalf("String() does not re-parse: %v", err)
		}
	})
}
