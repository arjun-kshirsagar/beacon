package mesh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/noise"
)

// Direct messages run over Noise XX sessions between two identities. Relays
// see only the handshake and ciphertext. See docs/protocol-spec.md.
const (
	hsStep1, hsStep2, hsStep3 = 1, 2, 3

	handshakeRetry   = 10 * time.Second
	handshakeTries   = 3
	responderTimeout = 30 * time.Second
	outboxFor        = 2 * time.Minute
	maxOutbox        = 32 // queued messages per peer
	maxHandshakes    = 64 // handshakes in progress, each side
	maxSessions      = 256
	replayWindow     = 256
	innerText        = 0x01
	innerData        = 0x02
)

var (
	// ErrUnknownPeer is returned when messaging a fingerprint not heard from.
	ErrUnknownPeer = errors.New("mesh: unknown peer")
	// ErrOutboxFull is returned when too many messages wait for a session.
	ErrOutboxFull = errors.New("mesh: too many messages waiting for this peer")
)

// noisePrologue binds handshakes to this protocol version.
var noisePrologue = []byte("beacon-mesh-v1")

// paddedSizes are the lengths a direct message's plaintext is padded to, so
// ciphertext length says little about the text.
var paddedSizes = []int{64, 128, 256, 512, 1024, 2048}

type dmState struct {
	sessions   map[Fingerprint]*session
	initiators map[Fingerprint]*initiator // handshakes we started, by target
	responders map[PeerID]*responder      // handshakes others started, by sender ID
	outbox     map[Fingerprint][]queued
	idToFP     map[PeerID]Fingerprint // sender IDs learned from handshakes
}

type session struct {
	send, recv *noise.CipherState
	sendN      uint64
	window     window
	peerID     PeerID
	used       time.Time
	// prev is the session this one replaced. Its messages may still be in
	// flight, so it keeps decrypting until the next replacement.
	prev *session
}

type initiator struct {
	hs      *noise.Handshake
	peerID  PeerID
	started time.Time
	tries   int
}

type responder struct {
	hs      *noise.Handshake
	started time.Time
}

type queued struct {
	kind byte
	body []byte
	at   time.Time
}

func (d *dmState) init() {
	d.sessions = make(map[Fingerprint]*session)
	d.initiators = make(map[Fingerprint]*initiator)
	d.responders = make(map[PeerID]*responder)
	d.outbox = make(map[Fingerprint][]queued)
	d.idToFP = make(map[PeerID]Fingerprint)
}

// rotated is called when our ID changes. Handshakes in flight were addressed
// to the old ID, which stays valid for a period, so nothing needs undoing.
func (d *dmState) rotated() {}

// SendDirect sends text, end-to-end encrypted, to the peer with fingerprint
// fp. If no session exists yet the message waits while one is set up.
func (n *Node) SendDirect(fp Fingerprint, text string) error {
	if err := checkText(text); err != nil {
		return err
	}
	return n.sendDirect(fp, innerText, []byte(text))
}

// SendDirectData sends up to MaxData bytes, end-to-end encrypted, to the peer
// with fingerprint fp, for its OnData. It is for protocols layered on the mesh.
func (n *Node) SendDirectData(fp Fingerprint, data []byte) error {
	if len(data) == 0 || len(data) > MaxData {
		return fmt.Errorf("%w: data length %d", ErrPayload, len(data))
	}
	return n.sendDirect(fp, innerData, append([]byte(nil), data...))
}

func (n *Node) sendDirect(fp Fingerprint, kind byte, body []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	d := &n.dm
	if s := d.sessions[fp]; s != nil {
		id := n.peerIDLocked(fp, s.peerID)
		return n.sendEncryptedLocked(s, id, kind, body)
	}
	id, ok := n.latestID(fp)
	if !ok {
		return ErrUnknownPeer
	}
	if len(d.outbox[fp]) >= maxOutbox {
		return ErrOutboxFull
	}
	d.outbox[fp] = append(d.outbox[fp], queued{kind: kind, body: body, at: n.cfg.Now()})
	// A handshake either way will flush the outbox when it completes.
	if d.initiators[fp] == nil && d.responders[id] == nil {
		n.startHandshakeLocked(fp, id, 0)
	}
	return nil
}

// latestID returns the most recently announced ID for fp.
func (n *Node) latestID(fp Fingerprint) (PeerID, bool) {
	var id PeerID
	var at time.Time
	for pid, p := range n.peers {
		if p.fp == fp && p.lastSeen.After(at) {
			id, at = pid, p.lastSeen
		}
	}
	return id, !at.IsZero()
}

func (n *Node) peerIDLocked(fp Fingerprint, fallback PeerID) PeerID {
	if id, ok := n.latestID(fp); ok {
		return id
	}
	return fallback
}

func (n *Node) startHandshakeLocked(fp Fingerprint, to PeerID, tries int) {
	d := &n.dm
	if len(d.initiators) >= maxHandshakes {
		return
	}
	hs := noise.NewHandshake(noise.Config{Initiator: true, Static: n.id.noise, Prologue: noisePrologue})
	msg, err := hs.WriteMessage([]byte{hsStep1}, nil)
	if err != nil {
		return
	}
	d.initiators[fp] = &initiator{hs: hs, peerID: to, started: n.cfg.Now(), tries: tries + 1}
	n.originateLocked(&Packet{Type: TypeHandshake, Recipient: &to, Payload: msg})
}

func (n *Node) sendEncryptedLocked(s *session, to PeerID, kind byte, body []byte) error {
	plain := padInner(kind, body)
	p := &Packet{Type: TypeEncrypted, Recipient: &to}
	n.stampLocked(p)
	payload := binary.BigEndian.AppendUint64(nil, s.sendN)
	payload, err := s.send.EncryptNonce(payload, s.sendN, p.header(), plain)
	if err != nil {
		return fmt.Errorf("mesh: encrypting: %w", err)
	}
	s.sendN++
	s.used = p.Time
	p.Payload = payload
	n.sendStampedLocked(p)
	return nil
}

// padInner builds a direct message's plaintext: kind, length, body, padding.
func padInner(kind byte, body []byte) []byte {
	need := 3 + len(body)
	size := paddedSizes[len(paddedSizes)-1]
	for _, s := range paddedSizes {
		if s >= need {
			size = s
			break
		}
	}
	b := make([]byte, size)
	b[0] = kind
	binary.BigEndian.PutUint16(b[1:], uint16(len(body)))
	copy(b[3:], body)
	return b
}

func padText(text string) []byte { return padInner(innerText, []byte(text)) }

// unpadInner checks a direct message's plaintext and returns its kind and body.
func unpadInner(b []byte) (byte, []byte, error) {
	if len(b) < 3 || b[0] != innerText && b[0] != innerData {
		return 0, nil, fmt.Errorf("%w: inner message", ErrPayload)
	}
	n := int(binary.BigEndian.Uint16(b[1:]))
	if n > len(b)-3 {
		return 0, nil, fmt.Errorf("%w: inner length", ErrPayload)
	}
	body := b[3 : 3+n]
	switch b[0] {
	case innerText:
		return innerText, body, checkText(string(body))
	default:
		if n == 0 || n > MaxData {
			return 0, nil, fmt.Errorf("%w: data length", ErrPayload)
		}
		return innerData, append([]byte(nil), body...), nil
	}
}

func unpadText(b []byte) (string, error) {
	kind, body, err := unpadInner(b)
	if err == nil && kind != innerText {
		err = fmt.Errorf("%w: not text", ErrPayload)
	}
	return string(body), err
}

// handle processes a directed packet addressed to us.
func (d *dmState) handle(n *Node, p *Packet, now time.Time) []Message {
	switch p.Type {
	case TypeHandshake:
		if len(p.Payload) < 1 {
			return nil
		}
		msg := p.Payload[1:]
		switch p.Payload[0] {
		case hsStep1:
			d.handleStep1(n, p.Sender, msg, now)
		case hsStep2:
			d.handleStep2(n, p.Sender, msg, now)
		case hsStep3:
			d.handleStep3(n, p.Sender, msg, now)
		}
	case TypeEncrypted:
		return d.handleEncrypted(n, p, now)
	}
	return nil
}

func (d *dmState) handleStep1(n *Node, from PeerID, msg []byte, now time.Time) {
	// If we are also initiating to this peer, both handshakes would cross.
	// The side with the lower Noise key stays initiator.
	if peer := n.peers[from]; peer != nil && d.initiators[peer.fp] != nil {
		mine := n.id.NoiseKey()
		if bytes.Compare(mine[:], peer.noiseKey[:]) < 0 {
			return
		}
		delete(d.initiators, peer.fp)
	}
	if d.responders[from] == nil && len(d.responders) >= maxHandshakes {
		d.dropOldestResponder()
	}
	hs := noise.NewHandshake(noise.Config{Static: n.id.noise, Prologue: noisePrologue})
	if _, err := hs.ReadMessage(nil, msg); err != nil {
		return
	}
	reply, err := hs.WriteMessage([]byte{hsStep2}, n.id.identityProof())
	if err != nil {
		return
	}
	d.responders[from] = &responder{hs: hs, started: now}
	n.originateLocked(&Packet{Type: TypeHandshake, Recipient: &from, Payload: reply})
}

func (d *dmState) dropOldestResponder() {
	var oldest PeerID
	var at time.Time
	for id, r := range d.responders {
		if at.IsZero() || r.started.Before(at) {
			oldest, at = id, r.started
		}
	}
	delete(d.responders, oldest)
}

func (d *dmState) handleStep2(n *Node, from PeerID, msg []byte, now time.Time) {
	var fp Fingerprint
	var in *initiator
	for f, i := range d.initiators {
		if i.peerID == from {
			fp, in = f, i
			break
		}
	}
	if in == nil {
		return
	}
	payload, err := in.hs.ReadMessage(nil, msg)
	if err != nil {
		delete(d.initiators, fp)
		return
	}
	static, _ := in.hs.PeerStatic()
	signKey, ok := checkProof(payload, static)
	if !ok || FingerprintOf(signKey) != fp {
		// Not who we meant to reach: abandon without revealing ourselves.
		n.log.Warn("handshake answered by the wrong identity", "want", fp.Short())
		delete(d.initiators, fp)
		return
	}
	reply, err := in.hs.WriteMessage([]byte{hsStep3}, n.id.identityProof())
	if err != nil {
		delete(d.initiators, fp)
		return
	}
	n.originateLocked(&Packet{Type: TypeHandshake, Recipient: &from, Payload: reply})
	delete(d.initiators, fp)
	d.establish(n, fp, from, in.hs, now)
}

func (d *dmState) handleStep3(n *Node, from PeerID, msg []byte, now time.Time) {
	r := d.responders[from]
	if r == nil {
		return
	}
	delete(d.responders, from)
	payload, err := r.hs.ReadMessage(nil, msg)
	if err != nil {
		return
	}
	static, _ := r.hs.PeerStatic()
	signKey, ok := checkProof(payload, static)
	if !ok {
		return
	}
	fp := FingerprintOf(signKey)
	if peer := n.peers[from]; peer != nil && peer.fp != fp {
		return // the ID belongs to someone else
	}
	d.establish(n, fp, from, r.hs, now)
}

func (d *dmState) establish(n *Node, fp Fingerprint, peerID PeerID, hs *noise.Handshake, now time.Time) {
	send, recv, err := hs.Split()
	if err != nil {
		return
	}
	if d.sessions[fp] == nil && len(d.sessions) >= maxSessions {
		d.dropOldestSession()
	}
	s := &session{send: send, recv: recv, peerID: peerID, used: now}
	if old := d.sessions[fp]; old != nil {
		old.prev = nil
		s.prev = old
	}
	d.sessions[fp] = s
	d.idToFP[peerID] = fp
	n.log.Debug("session established", "peer", fp.Short())
	for _, q := range d.outbox[fp] {
		n.sendEncryptedLocked(s, peerID, q.kind, q.body)
	}
	delete(d.outbox, fp)
}

func (d *dmState) dropOldestSession() {
	var oldest Fingerprint
	var at time.Time
	for fp, s := range d.sessions {
		if at.IsZero() || s.used.Before(at) {
			oldest, at = fp, s.used
		}
	}
	delete(d.sessions, oldest)
}

func (d *dmState) handleEncrypted(n *Node, p *Packet, now time.Time) []Message {
	fp, ok := d.idToFP[p.Sender]
	if peer := n.peers[p.Sender]; peer != nil {
		fp, ok = peer.fp, true
	}
	s := d.sessions[fp]
	if !ok || s == nil {
		// The sender has a session we lost (we restarted, say). Offer a fresh
		// one; this message is gone, later ones will get through.
		if ok && d.initiators[fp] == nil {
			n.startHandshakeLocked(fp, p.Sender, 0)
		}
		return nil
	}
	if len(p.Payload) < 8+noise.Overhead {
		return nil
	}
	nonce := binary.BigEndian.Uint64(p.Payload)
	var plain []byte
	for _, try := range []*session{s, s.prev} {
		if try == nil || !try.window.fresh(nonce) {
			continue
		}
		var err error
		if plain, err = try.recv.DecryptNonce(nil, nonce, p.header(), p.Payload[8:]); err == nil {
			try.window.mark(nonce)
			break
		}
	}
	if plain == nil {
		return nil
	}
	s.used = now
	s.peerID = p.Sender
	d.idToFP[p.Sender] = fp
	kind, body, err := unpadInner(plain)
	if err != nil {
		return nil
	}
	n.stats.Delivered++
	if kind == innerData {
		return []Message{{From: fp, Time: p.Time, data: body}}
	}
	nick := ""
	if peer := n.peers[p.Sender]; peer != nil {
		nick = peer.nickname
	}
	return []Message{{From: fp, Nickname: nick, Text: string(body), Time: p.Time}}
}

// tick retries stalled handshakes and expires old state.
func (d *dmState) tick(n *Node, now time.Time) {
	for fp, in := range d.initiators {
		if now.Sub(in.started) < handshakeRetry {
			continue
		}
		delete(d.initiators, fp)
		if in.tries < handshakeTries && len(d.outbox[fp]) > 0 {
			n.startHandshakeLocked(fp, n.peerIDLocked(fp, in.peerID), in.tries)
		}
	}
	for id, r := range d.responders {
		if now.Sub(r.started) > responderTimeout {
			delete(d.responders, id)
		}
	}
	for fp, q := range d.outbox {
		i := 0
		for i < len(q) && now.Sub(q[i].at) > outboxFor {
			i++
		}
		if i == len(q) {
			delete(d.outbox, fp)
		} else {
			d.outbox[fp] = q[i:]
		}
	}
	if len(d.idToFP) > 4*maxSessions {
		clear(d.idToFP)
		for fp, s := range d.sessions {
			d.idToFP[s.peerID] = fp
		}
	}
}

// window rejects replayed nonces. Mesh packets can arrive out of order, so it
// accepts any nonce within replayWindow of the highest seen, once.
type window struct {
	max  uint64
	any  bool
	bits [replayWindow / 64]uint64
}

func (w *window) bit(n uint64) (int, uint64) {
	i := n % replayWindow
	return int(i / 64), 1 << (i % 64)
}

func (w *window) fresh(n uint64) bool {
	if !w.any || n > w.max {
		return true
	}
	if w.max-n >= replayWindow {
		return false
	}
	i, b := w.bit(n)
	return w.bits[i]&b == 0
}

// mark records n, which must have passed fresh.
func (w *window) mark(n uint64) {
	if !w.any || n > w.max {
		if !w.any || n-w.max >= replayWindow {
			clear(w.bits[:])
		} else {
			for m := w.max + 1; m < n; m++ {
				i, b := w.bit(m)
				w.bits[i] &^= b
			}
		}
		w.max, w.any = n, true
	}
	i, b := w.bit(n)
	w.bits[i] |= b
}
