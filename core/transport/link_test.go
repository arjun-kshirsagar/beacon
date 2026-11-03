package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestRadio(t *testing.T) {
	r := NewRadio(20)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Connect("a", "b"); err != nil {
		t.Fatal(err)
	}
	if r.Connect("b", "a") == nil {
		t.Fatal("linked twice")
	}
	la, _ := r.Node("a").Accept(ctx)
	lb, _ := r.Node("b").Accept(ctx)
	if la.Peer() != "b" || lb.Peer() != "a" || la.MTU() != 20 {
		t.Fatalf("peers %s %s mtu %d", la.Peer(), lb.Peer(), la.MTU())
	}
	if err := la.WriteFrame([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if f, err := lb.ReadFrame(); err != nil || string(f) != "hello" {
		t.Fatalf("%q %v", f, err)
	}
	if !errors.Is(la.WriteFrame(make([]byte, 21)), ErrFrameTooLarge) {
		t.Fatal("oversized frame sent")
	}

	r.Disconnect("a", "b")
	if _, err := lb.ReadFrame(); err == nil {
		t.Fatal("read from a broken link")
	}
	if la.WriteFrame([]byte("x")) == nil {
		t.Fatal("wrote to a broken link")
	}
	// Back in range: a fresh link.
	if err := r.Connect("a", "b"); err != nil {
		t.Fatal(err)
	}
	// A link closed by one end can also be re-made.
	la, _ = r.Node("a").Accept(ctx)
	la.Close()
	if err := r.Connect("a", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamLink(t *testing.T) {
	a, b := net.Pipe()
	la, lb := NewStreamLink(a, 100, "b"), NewStreamLink(b, 100, "a")
	go func() {
		la.WriteFrame([]byte("one"))
		la.WriteFrame(make([]byte, 100))
	}()
	if f, err := lb.ReadFrame(); err != nil || string(f) != "one" {
		t.Fatalf("%q %v", f, err)
	}
	if f, err := lb.ReadFrame(); err != nil || len(f) != 100 {
		t.Fatalf("%d bytes, %v", len(f), err)
	}
	if !errors.Is(la.WriteFrame(make([]byte, 101)), ErrFrameTooLarge) || la.WriteFrame(nil) == nil {
		t.Fatal("bad frame sent")
	}
	// A peer announcing a frame over the MTU is refused before any allocation.
	go a.Write([]byte{0xff, 0xff})
	if _, err := lb.ReadFrame(); err == nil {
		t.Fatal("oversized frame accepted")
	}
	la.Close()
}
