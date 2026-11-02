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
	return m.listenPacket(addr, "")
}

// ListenMulticast joins group with a unique, non-IP source address.
func (m *Memory) ListenMulticast(group string) (net.PacketConn, error) {
	return m.listenPacket("", group)
}

// MulticastFrom returns a MulticastTransport whose sockets send from ip, so
// receivers see an IP address as they would on a real LAN.
func (m *Memory) MulticastFrom(ip string) MulticastTransport {
	return memHost{m: m, ip: ip}
}

type memHost struct {
	m  *Memory
	ip string
}

func (h memHost) ResolveAddr(ctx context.Context, addr string) (net.Addr, error) {
	return h.m.ResolveAddr(ctx, addr)
}

func (h memHost) ListenMulticast(group string) (net.PacketConn, error) {
	_, port, err := net.SplitHostPort(group)
	if err != nil {
		return nil, err
	}
	return h.m.listenPacket(net.JoinHostPort(h.ip, port), group)
}

func (m *Memory) listenPacket(addr, group string) (net.PacketConn, error) {
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
		group: group,
	}
	m.packets[addr] = c
	if group != "" {
		if m.groups == nil {
			m.groups = make(map[string]map[*memPacketConn]bool)
		}
		if m.groups[group] == nil {
			m.groups[group] = make(map[*memPacketConn]bool)
		}
		m.groups[group][c] = true
	}
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
	group string        // multicast group joined, if any

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
	var dsts []*memPacketConn
	if members, ok := c.net.groups[addr.String()]; ok {
		for d := range members { // multicast reaches every member, sender included
			dsts = append(dsts, d)
		}
	} else if d := c.net.packets[addr.String()]; d != nil {
		dsts = append(dsts, d)
	}
	c.net.mu.Unlock()
	for _, dst := range dsts {
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
		if c.group != "" {
			delete(c.net.groups[c.group], c)
		}
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
