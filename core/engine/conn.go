package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
)

const (
	maxBacklog = 32 // outstanding block requests per peer
	ctrlQueue  = 256
	dataQueue  = 4
)

var (
	errSelf      = errors.New("engine: connected to ourselves")
	errDuplicate = errors.New("engine: already connected to this peer")
	errSnubbed   = errors.New("engine: peer stopped sending requested blocks")
	errClosed    = errors.New("engine: connection closed")
)

// peerConn is one connection to a peer. Fields below the mutex note are guarded
// by Client.mu.
type peerConn struct {
	c       *Client
	conn    net.Conn
	addr    string
	key     string // ban key
	ctrl    chan *peer.Message
	data    chan *peer.Message // piece uploads, which may block
	closed  chan struct{}
	closeMu sync.Once

	// Guarded by Client.mu.
	id             [20]byte
	encrypted      bool // the stream is RC4-encrypted
	has            peer.Bitfield
	gotPieces      bool // a bitfield or have arrived; a later bitfield is invalid
	peerChoking    bool
	peerInterested bool
	amChoking      bool
	amInterested   bool
	optimistic     bool
	outstanding    map[blockRef]bool
	rateDown       int64 // bytes received since the last rechoke
	rateUp         int64 // bytes sent since the last rechoke
	lastBlock      time.Time
	extMetadata    int // the peer's ut_metadata message ID; 0 if unsupported
	extPEX         int // the peer's ut_pex message ID; 0 if unsupported
	outgoing       bool
	listenAddr     string          // where others can reach this peer; "" if unknown
	pexSent        map[string]bool // addresses we have told this peer about
	lastPEXIn      time.Time
}

func (pc *peerConn) close() {
	pc.closeMu.Do(func() {
		close(pc.closed)
		pc.conn.Close()
	})
}

// queue sends a small message without blocking; a peer too slow to drain its
// queue is disconnected.
func (pc *peerConn) queue(m *peer.Message) {
	select {
	case pc.ctrl <- m:
	default:
		pc.close()
	}
}

// queueData sends a large message, waiting for room. It must not be called with
// Client.mu held.
func (pc *peerConn) queueData(m *peer.Message) error {
	t := time.NewTimer(ioTimeout)
	defer t.Stop()
	select {
	case pc.data <- m:
		return nil
	case <-pc.closed:
		return errClosed
	case <-t.C:
		pc.close()
		return errClosed
	}
}

// runConn handshakes on conn and serves it until it fails. Outgoing connections
// have already been through secureDial; incoming ones go through secureAccept
// here. The caller has counted the connection in Client.dialing.
func (c *Client) runConn(ctx context.Context, conn net.Conn, addr string, outgoing, encrypted bool) error {
	pc := &peerConn{
		c:           c,
		conn:        conn,
		addr:        addr,
		key:         banKey(addr),
		ctrl:        make(chan *peer.Message, ctrlQueue),
		data:        make(chan *peer.Message, dataQueue),
		closed:      make(chan struct{}),
		has:         peer.NewBitfield(c.t.NumPieces()),
		peerChoking: true,
		amChoking:   true,
		outgoing:    outgoing,
		outstanding: make(map[blockRef]bool),
		pexSent:     make(map[string]bool),
	}
	defer pc.close()
	defer context.AfterFunc(ctx, pc.close)()

	var err error
	if !outgoing {
		conn, encrypted, err = secureAccept(conn, c.t.InfoHash, c.enc)
		if conn != nil {
			pc.conn = conn
		}
	}
	pc.encrypted = encrypted
	var theirs peer.Handshake
	if err == nil {
		theirs, err = c.handshake(conn, outgoing)
	}
	if err == nil {
		err = c.register(pc, theirs)
	}
	if err != nil {
		c.mu.Lock()
		c.dialing--
		c.mu.Unlock()
		c.signal()
		return err
	}
	defer c.unregister(pc)

	go pc.writeLoop()
	msgs := make(chan *peer.Message)
	errc := make(chan error, 1)
	go pc.readLoop(msgs, errc)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case m := <-msgs:
			if err := pc.handle(m); err != nil {
				return err
			}
		case err := <-errc:
			return err
		case <-pc.closed:
			return errClosed
		case <-tick.C:
			c.mu.Lock()
			snubbed := len(pc.outstanding) > 0 && time.Since(pc.lastBlock) > snubTimeout
			c.mu.Unlock()
			if snubbed {
				return errSnubbed
			}
		}
	}
}

func (c *Client) handshake(conn net.Conn, outgoing bool) (peer.Handshake, error) {
	conn.SetDeadline(time.Now().Add(ioTimeout))
	defer conn.SetDeadline(time.Time{})
	ours := peer.Handshake{InfoHash: c.t.InfoHash, PeerID: c.peerID}
	ours.SetExtensions()
	if outgoing {
		if _, err := ours.WriteTo(conn); err != nil {
			return peer.Handshake{}, err
		}
	}
	theirs, err := peer.ReadHandshake(conn)
	if err != nil {
		return peer.Handshake{}, err
	}
	if theirs.InfoHash != c.t.InfoHash {
		return peer.Handshake{}, ErrWrongTorrent
	}
	if theirs.PeerID == c.peerID {
		return peer.Handshake{}, errSelf
	}
	if !outgoing {
		if _, err := ours.WriteTo(conn); err != nil {
			return peer.Handshake{}, err
		}
	}
	return theirs, nil
}

func (c *Client) register(pc *peerConn, h peer.Handshake) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.banned[pc.key] {
		return ErrBanned
	}
	if c.peerIDs[h.PeerID] {
		return errDuplicate
	}
	pc.id = h.PeerID
	if pc.outgoing {
		pc.listenAddr = pc.addr
	}
	c.dialing--
	c.conns[pc] = true
	c.peerIDs[h.PeerID] = true
	if c.pk.have.Count() > 0 {
		pc.queue(&peer.Message{ID: peer.MsgBitfield, Payload: append([]byte(nil), c.pk.have...)})
	}
	if h.SupportsExtensions() {
		m := map[string]int{peer.ExtMetadata: metadataExtID}
		if !c.t.Private { // BEP 27: private torrents get peers from trackers only
			m[peer.ExtPEX] = pexExtID
		}
		eh := peer.ExtHandshake{
			M:            m,
			MetadataSize: len(c.t.InfoBytes),
			Version:      clientVersion,
			Port:         int(c.port),
		}
		pc.queue(peer.Extended(peer.ExtHandshakeID, eh.Encode()))
	}
	return nil
}

func (c *Client) unregister(pc *peerConn) {
	pc.close()
	c.mu.Lock()
	c.pk.release(pc)
	for i := range c.t.NumPieces() {
		if pc.has.Has(i) {
			c.pk.avail[i]--
		}
	}
	delete(c.conns, pc)
	delete(c.peerIDs, pc.id)
	c.mu.Unlock()
	c.signal()
}

func (pc *peerConn) readLoop(msgs chan<- *peer.Message, errc chan<- error) {
	for {
		pc.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		m, err := peer.ReadMessage(pc.conn, pc.c.maxMsg)
		if err != nil {
			errc <- err
			return
		}
		select {
		case msgs <- m:
		case <-pc.closed:
			return
		}
	}
}

func (pc *peerConn) writeLoop() {
	keepAlive := time.NewTimer(keepAliveInterval)
	defer keepAlive.Stop()
	for {
		var m *peer.Message // nil is a keep-alive
		select {
		case m = <-pc.ctrl:
		case m = <-pc.data:
		case <-keepAlive.C:
		case <-pc.closed:
			return
		}
		pc.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
		if err := peer.WriteMessage(pc.conn, m); err != nil {
			pc.close()
			return
		}
		keepAlive.Reset(keepAliveInterval)
	}
}

// handle processes one message from the peer.
func (pc *peerConn) handle(m *peer.Message) error {
	if m == nil {
		return nil
	}
	c := pc.c
	switch m.ID {
	case peer.MsgChoke:
		c.mu.Lock()
		pc.peerChoking = true
		c.pk.release(pc)
		c.mu.Unlock()
	case peer.MsgUnchoke:
		c.mu.Lock()
		pc.peerChoking = false
		pc.fill()
		c.mu.Unlock()
	case peer.MsgInterested:
		c.mu.Lock()
		pc.peerInterested = true
		if pc.amChoking && c.unchoked() < uploadSlots {
			pc.setChoking(false)
		}
		c.mu.Unlock()
	case peer.MsgNotInterested:
		c.mu.Lock()
		pc.peerInterested = false
		c.mu.Unlock()
	case peer.MsgHave:
		i, err := peer.ParseHave(m)
		if err != nil {
			return err
		}
		if int(i) >= c.t.NumPieces() {
			return fmt.Errorf("%w: have for piece %d", peer.ErrMalformed, i)
		}
		c.mu.Lock()
		pc.gotPieces = true
		if !pc.has.Has(int(i)) {
			pc.has.Set(int(i))
			c.pk.avail[i]++
		}
		pc.updateInterest()
		pc.fill()
		c.mu.Unlock()
	case peer.MsgBitfield:
		// The bitfield may follow an extension handshake (BEP 10 sends that
		// first), but must come before any have.
		bf, err := peer.ParseBitfield(m.Payload, c.t.NumPieces())
		if err != nil {
			return err
		}
		c.mu.Lock()
		if pc.gotPieces {
			c.mu.Unlock()
			return fmt.Errorf("%w: bitfield after have or bitfield", peer.ErrMalformed)
		}
		pc.gotPieces = true
		pc.has = bf
		for i := range c.t.NumPieces() {
			if bf.Has(i) {
				c.pk.avail[i]++
			}
		}
		pc.updateInterest()
		pc.fill()
		c.mu.Unlock()
	case peer.MsgRequest:
		return pc.serveRequest(m)
	case peer.MsgPiece:
		idx, begin, data, err := peer.ParsePiece(m)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if pc.outstanding[blockRef{int(idx), int(begin / BlockSize)}] {
			pc.rateDown += int64(len(data))
			pc.lastBlock = time.Now()
		}
		complete, cancels := c.pk.received(pc, int(idx), begin, data)
		for _, other := range cancels {
			other.queue(peer.Request(peer.MsgCancel, idx, begin, uint32(len(data))))
			other.fill()
		}
		pc.fill()
		c.mu.Unlock()
		if complete != nil {
			c.pieceDone(int(idx), complete)
		}
	case peer.MsgExtended:
		return pc.handleExtended(m)
	}
	return nil
}

func (pc *peerConn) serveRequest(m *peer.Message) error {
	c := pc.c
	idx, begin, length, err := peer.ParseRequest(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	have := int(idx) < c.t.NumPieces() && c.pk.have.Has(int(idx))
	choking := pc.amChoking
	c.mu.Unlock()
	if !have || length == 0 || length > MaxBlockSize || int64(begin)+int64(length) > c.t.PieceSize(int(idx)) {
		return fmt.Errorf("%w: piece %d [%d, +%d)", ErrBadRequest, idx, begin, length)
	}
	if choking {
		return nil // requests from choked peers are dropped
	}
	block := make([]byte, length)
	if _, err := c.store.ReadAt(block, int64(idx)*c.t.PieceLength+int64(begin)); err != nil {
		return err
	}
	if err := pc.queueData(peer.Piece(idx, begin, block)); err != nil {
		return err
	}
	c.mu.Lock()
	c.uploaded += int64(length)
	pc.rateUp += int64(length)
	c.mu.Unlock()
	return nil
}

func (pc *peerConn) handleExtended(m *peer.Message) error {
	c := pc.c
	id, body, err := peer.ParseExtended(m)
	if err != nil {
		return err
	}
	switch id {
	case peer.ExtHandshakeID:
		eh, err := peer.ParseExtHandshake(body)
		if err != nil {
			return err
		}
		c.mu.Lock()
		pc.extMetadata = eh.M[peer.ExtMetadata]
		pc.extPEX = eh.M[peer.ExtPEX]
		if !pc.outgoing && eh.Port > 0 {
			// An incoming peer's source port is ephemeral; its handshake tells
			// us the port it listens on.
			pc.listenAddr = net.JoinHostPort(banKey(pc.addr), strconv.Itoa(eh.Port))
		}
		c.mu.Unlock()
	case pexExtID:
		return pc.handlePEX(body)
	case metadataExtID:
		mm, err := peer.ParseMetadataMsg(body)
		if err != nil {
			return err
		}
		c.mu.Lock()
		theirID := pc.extMetadata
		c.mu.Unlock()
		if mm.Type != peer.MetadataRequest || theirID == 0 {
			return nil
		}
		info := c.t.InfoBytes
		start := mm.Piece * peer.MetadataPieceSize
		reply := peer.MetadataMsg{Type: peer.MetadataReject, Piece: mm.Piece}
		if start < len(info) {
			reply = peer.MetadataMsg{
				Type: peer.MetadataData, Piece: mm.Piece, TotalSize: len(info),
				Data: info[start:min(start+peer.MetadataPieceSize, len(info))],
			}
		}
		return pc.queueData(peer.Extended(uint8(theirID), reply.Encode()))
	}
	return nil
}

// handlePEX adds the peers a PEX message names. Messages arriving faster than
// half the PEX interval are ignored, so one peer cannot flood the dial queue.
func (pc *peerConn) handlePEX(body []byte) error {
	c := pc.c
	if c.t.Private {
		return nil
	}
	c.mu.Lock()
	tooSoon := time.Since(pc.lastPEXIn) < pexInterval/2
	if !tooSoon {
		pc.lastPEXIn = time.Now()
	}
	c.mu.Unlock()
	if tooSoon {
		return nil
	}
	p, err := peer.ParsePEX(body)
	if err != nil {
		return err
	}
	addrs := make([]string, len(p.Added))
	for i, a := range p.Added {
		addrs[i] = a.String()
	}
	c.AddPeers(addrs...)
	c.log.Debug("PEX supplied peers", "from", pc.addr, "added", len(p.Added), "dropped", len(p.Dropped))
	return nil
}

// The methods below require Client.mu.

// fill requests blocks until the backlog is full.
func (pc *peerConn) fill() {
	if pc.peerChoking || !pc.amInterested {
		return
	}
	n := maxBacklog - len(pc.outstanding)
	if n <= 0 {
		return
	}
	refs := pc.c.pk.pick(pc, n)
	if len(pc.outstanding) == 0 && len(refs) > 0 {
		pc.lastBlock = time.Now()
	}
	for _, ref := range refs {
		blk := &pc.c.pk.active[ref.piece].blocks[ref.block]
		blk.requesters = append(blk.requesters, pc)
		pc.outstanding[ref] = true
		pc.queue(peer.Request(peer.MsgRequest, uint32(ref.piece), uint32(ref.block*BlockSize),
			uint32(pc.c.pk.blockLen(ref.piece, ref.block))))
	}
}

// updateInterest tells the peer whether it has anything we lack.
func (pc *peerConn) updateInterest() {
	want := false
	for k := range pc.has {
		if pc.has[k]&^pc.c.pk.have[k] != 0 {
			want = true
			break
		}
	}
	if want == pc.amInterested {
		return
	}
	pc.amInterested = want
	if want {
		pc.queue(&peer.Message{ID: peer.MsgInterested})
	} else {
		pc.queue(&peer.Message{ID: peer.MsgNotInterested})
	}
}

func (pc *peerConn) setChoking(choke bool) {
	if pc.amChoking == choke {
		return
	}
	pc.amChoking = choke
	if choke {
		pc.queue(&peer.Message{ID: peer.MsgChoke})
	} else {
		pc.queue(&peer.Message{ID: peer.MsgUnchoke})
	}
}

func (c *Client) unchoked() int {
	n := 0
	for pc := range c.conns {
		if !pc.amChoking {
			n++
		}
	}
	return n
}
