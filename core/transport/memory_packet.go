package transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// packetQueue is how many datagrams an in-memory socket buffers before it drops
// new ones, as a full UDP socket buffer would.
const packetQueue = 1024

// ListenPacket opens an in-memory datagram socket. An empty addr picks a unique
// one. Use "ip:port" addresses for code, such as the DHT, that encodes them.
func (m *Memory) ListenPacket(addr string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.packets == nil {
		m.packets = make(map[string]*memPacketConn)
	}
	if addr == "" {
		m.next++
		addr = fmt.Sprintf("mem-udp-%d", m.next)
	}
	if _, ok := m.packets[addr]; ok {
		return nil, fmt.Errorf("transport: packet address %q already in use", addr)
	}
	c := &memPacketConn{
		net:   m,
		addr:  memAddr(addr),
		inbox: make(chan packet, packetQueue),
		done:  make(chan struct{}),
		wake:  make(chan struct{}, 1),
	}
	m.packets[addr] = c
	return c, nil
}

// ResolveAddr accepts any address string as is.
func (m *Memory) ResolveAddr(_ context.Context, addr string) (net.Addr, error) {
	return memAddr(addr), nil
}

type packet struct {
	data []byte
	from net.Addr
}

type memPacketConn struct {
	net   *Memory
	addr  memAddr
	inbox chan packet
	done  chan struct{}
	once  sync.Once
	wake  chan struct{} // signalled when the read deadline changes

	mu       sync.Mutex
	deadline time.Time
}

func (c *memPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case <-c.done:
			return 0, nil, net.ErrClosed
		default:
		}
		c.mu.Lock()
		deadline := c.deadline
		c.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case p := <-c.inbox:
			if timer != nil {
				timer.Stop()
			}
			return copy(b, p.data), p.from, nil
		case <-c.done:
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.wake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

// WriteTo delivers b to addr, silently dropping it if nobody listens there or the
// receiver's queue is full.
func (c *memPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.net.mu.Lock()
	dst := c.net.packets[addr.String()]
	c.net.mu.Unlock()
	if dst != nil {
		select {
		case dst.inbox <- packet{data: append([]byte(nil), b...), from: c.addr}:
		default:
		}
	}
	return len(b), nil
}

func (c *memPacketConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.net.mu.Lock()
		delete(c.net.packets, string(c.addr))
		c.net.mu.Unlock()
	})
	return nil
}

func (c *memPacketConn) LocalAddr() net.Addr { return c.addr }

func (c *memPacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func (c *memPacketConn) SetWriteDeadline(time.Time) error { return nil }
