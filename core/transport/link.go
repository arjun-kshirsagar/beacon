package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Link is a connection to one neighbouring device over a radio that carries
// small frames, such as a BLE GATT connection. Frames arrive whole and in
// order, or not at all.
type Link interface {
	// ReadFrame blocks until the next frame arrives.
	ReadFrame() ([]byte, error)
	// WriteFrame sends one frame of at most MTU bytes. It may block while
	// the radio is busy.
	WriteFrame(frame []byte) error
	// MTU is the largest frame the link carries.
	MTU() int
	// Peer names the neighbour, for logs and rate limits. It is chosen by the
	// platform (such as a BLE address) and proves nothing about identity.
	Peer() string
	Close() error
}

// LinkTransport hands over links to neighbours as the platform connects them.
// Discovery and connection policy live with the platform, not the mesh.
type LinkTransport interface {
	Accept(ctx context.Context) (Link, error)
}

// ErrFrameTooLarge is returned when writing a frame over the link's MTU.
var ErrFrameTooLarge = errors.New("transport: frame exceeds link MTU")

// Radio is an in-memory radio for mesh tests: named nodes joined by links
// that the test connects and disconnects to model devices moving in and out
// of range.
type Radio struct {
	mtu   int
	mu    sync.Mutex
	nodes map[string]*RadioNode
	links map[[2]string]*memLink // the a→b end, keyed with a < b
}

// NewRadio returns a radio whose links carry frames of up to mtu bytes.
func NewRadio(mtu int) *Radio {
	return &Radio{mtu: mtu, nodes: make(map[string]*RadioNode), links: make(map[[2]string]*memLink)}
}

// RadioNode is one device on a Radio. It implements LinkTransport.
type RadioNode struct {
	name   string
	accept chan Link
}

// Node returns the device called name, creating it on first use.
func (r *Radio) Node(name string) *RadioNode {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.nodes[name]
	if n == nil {
		n = &RadioNode{name: name, accept: make(chan Link, 64)}
		r.nodes[name] = n
	}
	return n
}

// Accept returns the next link to this node.
func (n *RadioNode) Accept(ctx context.Context) (Link, error) {
	select {
	case l := <-n.accept:
		return l, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func linkKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

// Connect brings a and b into range, giving each a link to the other.
func (r *Radio) Connect(a, b string) error {
	na, nb := r.Node(a), r.Node(b)
	r.mu.Lock()
	k := linkKey(a, b)
	if old := r.links[k]; a == b || old != nil && !old.closed() {
		r.mu.Unlock()
		return fmt.Errorf("transport: %s and %s already linked", a, b)
	}
	ab, ba := make(chan []byte, 32), make(chan []byte, 32)
	done := make(chan struct{})
	once := new(sync.Once)
	la := &memLink{peer: b, mtu: r.mtu, in: ba, out: ab, done: done, once: once}
	lb := &memLink{peer: a, mtu: r.mtu, in: ab, out: ba, done: done, once: once}
	r.links[k] = la
	r.mu.Unlock()
	select {
	case na.accept <- la:
	default:
		la.Close()
		return fmt.Errorf("transport: %s has too many pending links", a)
	}
	select {
	case nb.accept <- lb:
	default:
		la.Close()
		return fmt.Errorf("transport: %s has too many pending links", b)
	}
	return nil
}

// Disconnect takes a and b out of range, closing both ends of their link.
func (r *Radio) Disconnect(a, b string) {
	r.mu.Lock()
	k := linkKey(a, b)
	l := r.links[k]
	delete(r.links, k)
	r.mu.Unlock()
	if l != nil {
		l.Close()
	}
}

type memLink struct {
	peer    string
	mtu     int
	in, out chan []byte
	done    chan struct{} // shared by both ends: closing either breaks the link
	once    *sync.Once
}

func (l *memLink) ReadFrame() ([]byte, error) {
	select {
	case f := <-l.in:
		return f, nil
	case <-l.done:
		return nil, io.EOF
	}
}

func (l *memLink) WriteFrame(frame []byte) error {
	if len(frame) > l.mtu {
		return ErrFrameTooLarge
	}
	f := append([]byte(nil), frame...)
	select {
	case <-l.done:
		return io.ErrClosedPipe
	default:
	}
	select {
	case l.out <- f:
		return nil
	case <-l.done:
		return io.ErrClosedPipe
	}
}

func (l *memLink) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *memLink) MTU() int     { return l.mtu }
func (l *memLink) Peer() string { return l.peer }

func (l *memLink) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
