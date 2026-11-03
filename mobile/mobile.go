package mobile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"

	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// BLE GATT layout; see docs/protocol-spec.md.
const (
	// BLEServiceUUID is the GATT service every Beacon device runs and advertises.
	BLEServiceUUID = "6b1e0001-4c1a-4b8e-9f3d-be7ac0b3e500"
	// BLEFramesUUID is the characteristic that carries link frames: centrals
	// write to it, peripherals notify on it.
	BLEFramesUUID = "6b1e0002-4c1a-4b8e-9f3d-be7ac0b3e500"
	// InstanceSize is the length of the instance in BLE service data.
	InstanceSize = 8

	linkBuffer = 256 // received frames queued per link before dropping
)

// NewIdentity generates an identity and returns its private keys, for the
// platform to store (wrapped by the Android Keystore).
func NewIdentity() ([]byte, error) {
	id, err := mesh.NewIdentity()
	if err != nil {
		return nil, err
	}
	return id.Marshal(), nil
}

// Fingerprint returns the fingerprint of a stored identity.
func Fingerprint(identity []byte) (string, error) {
	id, err := mesh.UnmarshalIdentity(identity)
	if err != nil {
		return "", err
	}
	return string(id.Fingerprint()), nil
}

// CheckNickname returns an error if name cannot be used as a nickname.
func CheckNickname(name string) error { return mesh.CheckNickname(name) }

// NewInstance returns a random instance for BLE service data. It pairs up
// connections only; rotate it with the advertisement so it cannot be used to
// follow a device.
func NewInstance() []byte {
	b := make([]byte, InstanceSize)
	rand.Read(b)
	return b
}

// ShouldConnect reports whether the device with instance mine should open
// the BLE connection to the device advertising theirs. Exactly one side of
// every pair connects: the lower instance.
func ShouldConnect(mine, theirs []byte) bool {
	return len(mine) == InstanceSize && len(theirs) == InstanceSize && bytes.Compare(mine, theirs) < 0
}

// Listener receives what the node delivers. Methods are called on Go
// goroutines and must not block for long.
type Listener interface {
	// OnMessage delivers a message. channel is empty for a direct message.
	OnMessage(fromFingerprint, nickname, channel, text string, sentMillis int64)
}

// LinkHandler is the platform side of one radio link.
type LinkHandler interface {
	// SendFrame sends one frame of at most the link's MTU. It may block
	// until the radio accepts it and returns an error if the link is gone.
	SendFrame(frame []byte) error
	// Close disconnects the radio link. Go calls it when it gives up on a
	// link, such as one whose MTU is too small.
	Close()
}

// Node is a mesh node driven by the platform.
type Node struct {
	id     *mesh.Identity
	node   *mesh.Node
	links  *links
	cancel context.CancelFunc
	mu     sync.Mutex
	done   chan struct{}
	wiped  bool
}

// ErrWiped is returned after Wipe.
var ErrWiped = errors.New("mobile: node wiped")

// NewNode creates a node for a stored identity. Call Start to run it.
func NewNode(identity []byte, nickname string, l Listener) (*Node, error) {
	if l == nil {
		return nil, errors.New("mobile: nil listener")
	}
	id, err := mesh.UnmarshalIdentity(identity)
	if err != nil {
		return nil, err
	}
	ls := &links{ready: make(chan transport.Link, 64)}
	n, err := mesh.New(mesh.Config{Identity: id, Nickname: nickname, Links: ls,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnMessage: func(m mesh.Message) {
			l.OnMessage(string(m.From), m.Nickname, m.Channel, m.Text, m.Time.UnixMilli())
		}})
	if err != nil {
		return nil, err
	}
	return &Node{id: id, node: n, links: ls}, nil
}

// Start runs the node in the background. It may be called once.
func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.done != nil {
		return errors.New("mobile: node already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel, n.done = cancel, make(chan struct{})
	go func() {
		n.node.Run(ctx)
		close(n.done)
	}()
	return nil
}

// Stop shuts the node down and closes its links.
func (n *Node) Stop() {
	n.mu.Lock()
	cancel, done := n.cancel, n.done
	n.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	n.links.closeAll()
}

// Wipe stops the node and zeroes its keys in memory, for a panic wipe. The
// platform must also delete the stored identity.
func (n *Node) Wipe() {
	n.Stop()
	n.mu.Lock()
	n.wiped = true
	n.mu.Unlock()
	n.id.Wipe()
}

func (n *Node) usable() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.wiped {
		return ErrWiped
	}
	return nil
}

// Fingerprint returns this node's fingerprint.
func (n *Node) Fingerprint() string { return string(n.node.Fingerprint()) }

// SendChannel broadcasts text to a channel such as "#general".
func (n *Node) SendChannel(channel, text string) error {
	if err := n.usable(); err != nil {
		return err
	}
	return n.node.SendChannel(channel, text)
}

// SendDirect sends text, end-to-end encrypted, to the peer with fingerprint.
func (n *Node) SendDirect(fingerprint, text string) error {
	if err := n.usable(); err != nil {
		return err
	}
	return n.node.SendDirect(mesh.Fingerprint(fingerprint), text)
}

type peerJSON struct {
	Fingerprint    string `json:"fingerprint"`
	Nickname       string `json:"nickname"`
	LastSeenMillis int64  `json:"lastSeenMillis"`
}

// PeersJSON lists peers heard from recently as a JSON array of objects with
// fingerprint, nickname and lastSeenMillis, sorted by nickname.
func (n *Node) PeersJSON() string {
	var out []peerJSON
	for _, p := range n.node.Peers() {
		out = append(out, peerJSON{string(p.Fingerprint), p.Nickname, p.LastSeen.UnixMilli()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nickname < out[j].Nickname })
	b, _ := json.Marshal(out)
	if out == nil {
		return "[]"
	}
	return string(b)
}

// StatsJSON returns the node's counters as a JSON object.
func (n *Node) StatsJSON() string {
	b, _ := json.Marshal(n.node.Stats())
	return string(b)
}

// LinkUp registers a new radio link to a neighbour. peer names it for logs
// (such as a BLE address) and mtu is the largest frame it carries.
func (n *Node) LinkUp(peer string, mtu int, h LinkHandler) (*Link, error) {
	if h == nil {
		return nil, errors.New("mobile: nil link handler")
	}
	k := &Link{peer: peer, mtu: mtu, h: h, owner: n.links, in: make(chan []byte, linkBuffer), done: make(chan struct{})}
	if !n.links.add(k) {
		return nil, errors.New("mobile: too many pending links")
	}
	return k, nil
}

// Link is one radio link as seen by Go. It implements transport.Link.
type Link struct {
	peer  string
	mtu   int
	h     LinkHandler
	owner *links
	in    chan []byte
	done  chan struct{}
	once  sync.Once
}

// Receive hands Go a frame that arrived on the link. It never blocks: if
// Go is behind, the frame is dropped and the mesh recovers at the next
// packet boundary.
func (k *Link) Receive(frame []byte) {
	f := append([]byte(nil), frame...)
	select {
	case k.in <- f:
	case <-k.done:
	default:
	}
}

// Down reports that the radio link was lost.
func (k *Link) Down() { k.shut() }

func (k *Link) shut() bool {
	closed := false
	k.once.Do(func() { close(k.done); closed = true })
	if closed {
		k.owner.remove(k)
	}
	return closed
}

// ReadFrame implements transport.Link.
func (k *Link) ReadFrame() ([]byte, error) {
	select {
	case f := <-k.in:
		return f, nil
	case <-k.done:
		return nil, io.EOF
	}
}

// WriteFrame implements transport.Link.
func (k *Link) WriteFrame(frame []byte) error {
	select {
	case <-k.done:
		return io.ErrClosedPipe
	default:
	}
	if len(frame) > k.mtu {
		return transport.ErrFrameTooLarge
	}
	return k.h.SendFrame(frame)
}

// MTU implements transport.Link.
func (k *Link) MTU() int { return k.mtu }

// Peer implements transport.Link.
func (k *Link) Peer() string { return k.peer }

// Close implements transport.Link: Go is done with the link, so the radio
// connection is dropped too.
func (k *Link) Close() error {
	if k.shut() {
		go k.h.Close() // the platform may call back into Go
	}
	return nil
}

// links hands platform links to the mesh node.
type links struct {
	ready chan transport.Link
	mu    sync.Mutex
	all   map[*Link]bool
}

func (l *links) add(k *Link) bool {
	l.mu.Lock()
	if l.all == nil {
		l.all = make(map[*Link]bool)
	}
	l.all[k] = true
	l.mu.Unlock()
	select {
	case l.ready <- k:
		return true
	default:
		l.remove(k)
		return false
	}
}

func (l *links) remove(k *Link) {
	l.mu.Lock()
	delete(l.all, k)
	l.mu.Unlock()
}

func (l *links) Accept(ctx context.Context) (transport.Link, error) {
	select {
	case k := <-l.ready:
		return k, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *links) closeAll() {
	l.mu.Lock()
	var all []*Link
	for k := range l.all {
		all = append(all, k)
	}
	l.mu.Unlock()
	for _, k := range all {
		k.Close()
	}
}
