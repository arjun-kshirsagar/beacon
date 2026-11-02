package tracker

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name string
		resp map[string]any
		want *Response
	}{
		{
			name: "compact",
			resp: map[string]any{"interval": 900, "peers": "\x7f\x00\x00\x01\x1a\xe1\x0a\x00\x00\x02\x00\x50"},
			want: &Response{Interval: 900 * time.Second, Peers: []netip.AddrPort{
				netip.MustParseAddrPort("127.0.0.1:6881"), netip.MustParseAddrPort("10.0.0.2:80")}},
		},
		{
			name: "dictionary model",
			resp: map[string]any{"interval": 60, "peers": []any{
				map[string]any{"ip": "192.168.1.5", "port": 51413, "peer id": "x"},
				map[string]any{"ip": "not-an-ip", "port": 1},
				map[string]any{"ip": "10.0.0.1", "port": 0},
			}},
			want: &Response{Interval: time.Minute, Peers: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.5:51413")}},
		},
		{
			name: "ipv6 and garbage interval",
			resp: map[string]any{"interval": -5, "peers": "", "peers6": "\x20\x01\x0d\xb8" + string(make([]byte, 11)) + "\x01\x1a\xe1"},
			want: &Response{Interval: DefaultInterval, Peers: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:6881")}},
		},
		{
			name: "huge interval is capped",
			resp: map[string]any{"interval": int64(1) << 62},
			want: &Response{Interval: maxInterval},
		},
	}
	for _, tt := range tests {
		body, _ := bencode.Encode(tt.resp)
		got, err := ParseResponse(body)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestParseResponseErrors(t *testing.T) {
	tests := []struct {
		body string
		want error
	}{
		{"d14:failure reason6:bannede", ErrFailure},
		{"d5:peers5:abcdee", ErrBadResponse},
		{"d5:peersi1ee", ErrBadResponse},
		{"le", ErrBadResponse},
		{"<html>", ErrBadResponse},
	}
	for _, tt := range tests {
		if _, err := ParseResponse([]byte(tt.body)); !errors.Is(err, tt.want) {
			t.Errorf("%q: got %v, want %v", tt.body, err, tt.want)
		}
	}
}

func TestAnnounce(t *testing.T) {
	req := Request{Port: 6881, Left: 100, Event: EventStarted}
	copy(req.InfoHash[:], "\x00\xff info hash &=?%....")
	copy(req.PeerID[:], "-BC0001-abcdefghijkl")

	mux := http.NewServeMux()
	mux.HandleFunc("/announce", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("info_hash") != string(req.InfoHash[:]) || q.Get("peer_id") != string(req.PeerID[:]) {
			http.Error(w, "bad ids", http.StatusBadRequest)
			return
		}
		if q.Get("passkey") != "secret" || q.Get("port") != "6881" || q.Get("left") != "100" ||
			q.Get("event") != "started" || q.Get("compact") != "1" {
			http.Error(w, "bad query "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		w.Write([]byte("d8:intervali120e5:peers6:\x7f\x00\x00\x01\x1a\xe1e"))
	})

	net := transport.NewMemory()
	l, err := net.Listen("tracker:80")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	resp, err := AnnounceHTTP(context.Background(), NewHTTPClient(net), "http://tracker/announce?passkey=secret", req)
	if err != nil {
		t.Fatal(err)
	}
	want := &Response{Interval: 2 * time.Minute, Peers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:6881")}}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("got %+v, want %+v", resp, want)
	}

	if _, err := AnnounceHTTP(context.Background(), NewHTTPClient(net), "udp://tracker:80", req); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("udp: got %v", err)
	}
	if _, err := AnnounceHTTP(context.Background(), NewHTTPClient(net), "http://tracker/missing", req); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("404: got %v", err)
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte("d8:intervali120e5:peers6:\x7f\x00\x00\x01\x1a\xe1e"))
	f.Add([]byte("d5:peersld2:ip9:127.0.0.14:porti80eeee"))
	f.Add([]byte("d6:peers618:\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1a\xe1e"))
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseResponse(body)
		if err != nil {
			return
		}
		if r.Interval <= 0 || r.Interval > maxInterval {
			t.Fatalf("interval %v out of range", r.Interval)
		}
		for _, p := range r.Peers {
			if p.Port() == 0 || !p.Addr().IsValid() {
				t.Fatalf("invalid peer %v", p)
			}
		}
	})
}
