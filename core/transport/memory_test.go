package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestMemoryRoundTrip(t *testing.T) {
	m := NewMemory()
	l, err := m.Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		// Both sides write before reading; buffered pipes must not deadlock.
		if _, err := c.Write([]byte("pong")); err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			srvErr <- err
			return
		}
		if string(buf) != "ping" {
			srvErr <- errors.New("server got " + string(buf))
			return
		}
		srvErr <- nil
	}()

	c, err := m.Dial(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q", buf)
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	// The server closed its end: the client reads EOF.
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("read after peer close: got %v, want EOF", err)
	}
	c.Close()
	if _, err := c.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close: got %v, want ErrClosed", err)
	}
}

func TestMemoryDialUnknown(t *testing.T) {
	m := NewMemory()
	if _, err := m.Dial(context.Background(), "nowhere"); !errors.Is(err, ErrConnRefused) {
		t.Fatalf("got %v, want ErrConnRefused", err)
	}
}

func TestMemoryReadDeadline(t *testing.T) {
	m := NewMemory()
	l, _ := m.Listen("srv")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	c, err := m.Dial(context.Background(), "srv")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestMemoryPackets(t *testing.T) {
	m := NewMemory()
	a, err := m.ListenPacket("10.0.0.1:6881")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _ := m.ListenPacket("")
	defer b.Close()

	dst, _ := m.ResolveAddr(context.Background(), "10.0.0.1:6881")
	b.WriteTo([]byte("hello"), dst)
	// Datagrams to nowhere vanish without error, as with UDP.
	if _, err := b.WriteTo([]byte("lost"), memAddr("10.9.9.9:1")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, from, err := a.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" || from.String() != b.LocalAddr().String() {
		t.Fatalf("got %q from %v, %v", buf[:n], from, err)
	}
	a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := a.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
	a.Close()
	if _, _, err := a.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}

func TestMemoryMulticast(t *testing.T) {
	m := NewMemory()
	const group = "239.192.152.143:6771"
	a, err := m.MulticastFrom("10.0.0.1").ListenMulticast(group)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _ := m.MulticastFrom("10.0.0.2").ListenMulticast(group)
	defer b.Close()

	dst, _ := m.ResolveAddr(context.Background(), group)
	a.WriteTo([]byte("hi"), dst)
	for _, c := range []net.PacketConn{a, b} { // the sender hears itself, like loopback
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 8)
		n, from, err := c.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "hi" || from.String() != "10.0.0.1:6771" {
			t.Fatalf("got %q from %v, %v", buf[:n], from, err)
		}
	}
	b.Close()
	a.WriteTo([]byte("again"), dst) // closed members are gone from the group
	a.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := a.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
}
