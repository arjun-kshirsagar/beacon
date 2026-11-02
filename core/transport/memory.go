package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// ErrConnRefused is returned when dialing an address nobody listens on.
var ErrConnRefused = errors.New("transport: connection refused")

// Memory is an in-process network for tests. It implements both Transport and
// PacketTransport. Connections are buffered pipes, so both ends may write before
// reading without deadlocking, as with real sockets. Stream buffers are
// unbounded; Memory is not meant for production traffic.
type Memory struct {
	mu        sync.Mutex
	listeners map[string]*memListener
	packets   map[string]*memPacketConn
	next      int
}

// NewMemory returns an empty in-memory network.
func NewMemory() *Memory {
	return &Memory{listeners: make(map[string]*memListener)}
}

// Listen registers addr on the network. An empty addr picks a unique one.
func (m *Memory) Listen(addr string) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if addr == "" {
		m.next++
		addr = fmt.Sprintf("mem-%d", m.next)
	}
	if _, ok := m.listeners[addr]; ok {
		return nil, fmt.Errorf("transport: address %q already in use", addr)
	}
	l := &memListener{
		net:    m,
		addr:   memAddr(addr),
		accept: make(chan net.Conn),
		done:   make(chan struct{}),
	}
	m.listeners[addr] = l
	return l, nil
}

// Dial connects to a listener registered with Listen.
func (m *Memory) Dial(ctx context.Context, addr string) (net.Conn, error) {
	m.mu.Lock()
	l, ok := m.listeners[addr]
	m.next++
	local := memAddr(fmt.Sprintf("mem-client-%d", m.next))
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("dial %s: %w", addr, ErrConnRefused)
	}

	a, b := newPipe(), newPipe()
	client := newMemConn(a, b, local, l.addr)
	server := newMemConn(b, a, l.addr, local)
	select {
	case l.accept <- server:
		return client, nil
	case <-l.done:
		return nil, fmt.Errorf("dial %s: %w", addr, ErrConnRefused)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

type memListener struct {
	net    *Memory
	addr   memAddr
	accept chan net.Conn
	done   chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.net.mu.Lock()
		delete(l.net.listeners, string(l.addr))
		l.net.mu.Unlock()
	})
	return nil
}

func (l *memListener) Addr() net.Addr { return l.addr }

// pipe is one direction of a connection.
type pipe struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
	ready  chan struct{} // signalled when data arrives, the pipe closes or a deadline changes
}

func newPipe() *pipe { return &pipe{ready: make(chan struct{}, 1)} }

func (p *pipe) signal() {
	select {
	case p.ready <- struct{}{}:
	default:
	}
}

type memConn struct {
	in, out       *pipe
	local, remote memAddr
	done          chan struct{}
	once          sync.Once

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newMemConn(in, out *pipe, local, remote memAddr) *memConn {
	return &memConn{in: in, out: out, local: local, remote: remote, done: make(chan struct{})}
}

func (c *memConn) Read(b []byte) (int, error) {
	for {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		default:
		}
		c.in.mu.Lock()
		if c.in.buf.Len() > 0 {
			n, _ := c.in.buf.Read(b)
			c.in.mu.Unlock()
			return n, nil
		}
		closed := c.in.closed
		c.in.mu.Unlock()
		if closed {
			return 0, io.EOF
		}

		c.mu.Lock()
		deadline := c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		var err error
		select {
		case <-c.in.ready:
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-c.done:
			err = net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *memConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.out.mu.Lock()
	defer c.out.mu.Unlock()
	if c.out.closed {
		return 0, io.ErrClosedPipe
	}
	c.out.buf.Write(b)
	c.out.signal()
	return len(b), nil
}

func (c *memConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		for _, p := range []*pipe{c.in, c.out} {
			p.mu.Lock()
			p.closed = true
			p.signal()
			p.mu.Unlock()
		}
	})
	return nil
}

func (c *memConn) LocalAddr() net.Addr  { return c.local }
func (c *memConn) RemoteAddr() net.Addr { return c.remote }

func (c *memConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.in.signal()
	return nil
}

func (c *memConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
