package mse

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// tap records every byte written through a connection.
type tap struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (t *tap) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.out.Write(p)
	t.mu.Unlock()
	return t.Conn.Write(p)
}

func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	m := transport.NewMemory()
	l, err := m.Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	a, err := m.Dial(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

type result struct {
	conn   net.Conn
	ih     [20]byte
	method Method
	err    error
}

func runHandshake(t *testing.T, ih [20]byte, serve [][20]byte, provide, allow Method, ia []byte) (init, resp result, wire *tap) {
	t.Helper()
	a, b := pair(t)
	wire = &tap{Conn: a}
	done := make(chan result, 1)
	go func() {
		c, h, m, err := Accept(b, serve, allow)
		if err != nil {
			b.Close()
		}
		done <- result{c, h, m, err}
	}()
	c, m, err := initiate(wire, ih, provide, ia)
	init = result{conn: c, method: m, err: err}
	resp = <-done
	return init, resp, wire
}

func TestHandshakeMethods(t *testing.T) {
	ih := [20]byte{1, 2, 3}
	tests := []struct {
		provide, allow Method
		want           Method
		wantErr        error
	}{
		{RC4 | Plaintext, RC4 | Plaintext, RC4, nil},
		{RC4, RC4 | Plaintext, RC4, nil},
		{Plaintext, RC4 | Plaintext, Plaintext, nil},
		{RC4 | Plaintext, Plaintext, Plaintext, nil},
		{RC4, Plaintext, 0, ErrNoCommonMethod},
	}
	for _, tt := range tests {
		init, resp, wire := runHandshake(t, ih, [][20]byte{{9}, ih}, tt.provide, tt.allow, nil)
		if tt.wantErr != nil {
			if !errors.Is(resp.err, tt.wantErr) || init.err == nil {
				t.Errorf("provide %d allow %d: responder %v, initiator %v", tt.provide, tt.allow, resp.err, init.err)
			}
			continue
		}
		if init.err != nil || resp.err != nil {
			t.Fatalf("provide %d allow %d: %v / %v", tt.provide, tt.allow, init.err, resp.err)
		}
		if init.method != tt.want || resp.method != tt.want || resp.ih != ih {
			t.Fatalf("methods %d/%d, info-hash %x", init.method, resp.method, resp.ih)
		}

		// Payload flows both ways, and RC4 hides it from the wire.
		before := wire.out.Len()
		msg := []byte("\x13BitTorrent protocol, both directions")
		go init.conn.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(resp.conn, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("initiator→responder: %q, %v", got, err)
		}
		go resp.conn.Write(msg)
		if _, err := io.ReadFull(init.conn, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("responder→initiator: %q, %v", got, err)
		}
		visible := bytes.Contains(wire.out.Bytes()[before:], []byte("BitTorrent protocol"))
		if visible != (tt.want == Plaintext) {
			t.Errorf("method %d: payload visible on the wire = %v", tt.want, visible)
		}
	}
}

func TestInitialPayload(t *testing.T) {
	ih := [20]byte{7}
	ia := []byte("\x13BitTorrent protocol early handshake")
	init, resp, _ := runHandshake(t, ih, [][20]byte{ih}, RC4, RC4, ia)
	if init.err != nil || resp.err != nil {
		t.Fatal(init.err, resp.err)
	}
	got := make([]byte, len(ia))
	if _, err := io.ReadFull(resp.conn, got); err != nil || !bytes.Equal(got, ia) {
		t.Fatalf("IA = %q, %v", got, err)
	}
}

func TestUnknownTorrent(t *testing.T) {
	_, resp, _ := runHandshake(t, [20]byte{1}, [][20]byte{{2}, {3}}, RC4, RC4, nil)
	if !errors.Is(resp.err, ErrUnknownTorrent) {
		t.Fatalf("got %v", resp.err)
	}
}

func TestDegenerateKeyRejected(t *testing.T) {
	k, _ := newKey()
	for _, y := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(prime, big.NewInt(1)), prime} {
		if _, err := k.secret(pad96(y)); !errors.Is(err, ErrHandshake) {
			t.Errorf("Y=%v accepted", y)
		}
	}
	// Two honest keys agree on the secret.
	k2, _ := newKey()
	s1, _ := k.secret(k2.pub)
	s2, _ := k2.secret(k.pub)
	if !bytes.Equal(s1, s2) || len(s1) != keyLen {
		t.Fatal("DH secrets differ")
	}
}

func TestDetect(t *testing.T) {
	for _, tt := range []struct {
		first     string
		encrypted bool
	}{
		{"\x13BitTorrent protocol\x00\x00", false},
		{string(bytes.Repeat([]byte{0xab}, 30)), true},
	} {
		a, b := pair(t)
		go a.Write([]byte(tt.first))
		c, enc, err := Detect(b)
		if err != nil || enc != tt.encrypted {
			t.Fatalf("%q: encrypted=%v err=%v", tt.first[:4], enc, err)
		}
		got := make([]byte, len(tt.first))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != tt.first {
			t.Fatalf("replay = %q, %v", got, err)
		}
	}
}

// fakeConn reads from a fixed input and discards writes.
type fakeConn struct {
	net.Conn
	r io.Reader
}

func (f fakeConn) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f fakeConn) Write(p []byte) (int, error) { return len(p), nil }

func FuzzAccept(f *testing.F) {
	k, _ := newKey()
	f.Add(append(k.pub, make([]byte, 600)...))
	f.Add(bytes.Repeat([]byte{0xff}, 200))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must fail cleanly, never panic or read without bound.
		r := &countingReader{r: bytes.NewReader(data)}
		Accept(fakeConn{r: r}, [][20]byte{{1}}, RC4|Plaintext)
		if r.n > len(data) {
			t.Fatalf("read %d of %d bytes", r.n, len(data))
		}
	})
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
