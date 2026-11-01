package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	// BlockSize is the size of the blocks we request.
	BlockSize = 16 << 10
	// MaxBlockSize is the largest block we serve to a peer.
	MaxBlockSize = 128 << 10

	maxBacklog    = 8 // outstanding block requests per peer
	maxServeConns = 64
	dialTimeout   = 15 * time.Second
	ioTimeout     = 60 * time.Second
	pieceTimeout  = 2 * time.Minute
	idleTimeout   = 3 * time.Minute
)

var (
	// ErrIncomplete reports that every peer failed before the download finished.
	ErrIncomplete = errors.New("engine: download incomplete: no usable peers left")
	// ErrBadPiece reports a piece that failed its hash check.
	ErrBadPiece = errors.New("engine: piece failed hash check")
	// ErrWrongTorrent reports a peer handshaking for a different info-hash.
	ErrWrongTorrent = errors.New("engine: peer is on a different torrent")
	// ErrBadRequest reports a peer requesting data we cannot or will not serve.
	ErrBadRequest = errors.New("engine: invalid block request")
)

// Config configures a Client.
type Config struct {
	Transport transport.Transport
	PeerID    [20]byte // zero picks a random ID
	Logger    *slog.Logger
}

// Client downloads and seeds one torrent.
type Client struct {
	t      *torrent.Torrent
	store  *Storage
	tr     transport.Transport
	peerID [20]byte
	log    *slog.Logger
	maxMsg uint32

	mu         sync.Mutex
	have       peer.Bitfield
	downloaded int64
	uploaded   int64
	done       chan struct{} // closed once every piece is verified
}

// NewPeerID returns a random Azureus-style peer ID.
func NewPeerID() [20]byte {
	var id [20]byte
	copy(id[:], "-BC0001-")
	rand.Read(id[8:])
	return id
}

// New returns a client for t backed by store. It hashes the existing data first,
// so a partly downloaded torrent resumes and a complete one is ready to seed.
func New(t *torrent.Torrent, store *Storage, cfg Config) (*Client, error) {
	if cfg.Transport == nil {
		return nil, errors.New("engine: no transport configured")
	}
	have, err := Verify(t, store)
	if err != nil {
		return nil, err
	}
	c := &Client{
		t:      t,
		store:  store,
		tr:     cfg.Transport,
		peerID: cfg.PeerID,
		log:    cfg.Logger,
		maxMsg: uint32(max(1+len(have), 9+MaxBlockSize)),
		have:   have,
		done:   make(chan struct{}),
	}
	if c.peerID == ([20]byte{}) {
		c.peerID = NewPeerID()
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if have.Count() == t.NumPieces() {
		close(c.done)
	}
	return c, nil
}

// PeerID returns the client's peer ID.
func (c *Client) PeerID() [20]byte { return c.peerID }

// Done is closed once the torrent is complete.
func (c *Client) Done() <-chan struct{} { return c.done }

// Stats describes a client's progress.
type Stats struct {
	Pieces, TotalPieces  int
	Downloaded, Uploaded int64
	Left                 int64
}

// Stats returns current progress.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{Pieces: c.have.Count(), TotalPieces: c.t.NumPieces(), Downloaded: c.downloaded, Uploaded: c.uploaded}
	for i := range c.t.NumPieces() {
		if !c.have.Has(i) {
			s.Left += c.t.PieceSize(i)
		}
	}
	return s
}

func (c *Client) hasPiece(i int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return i >= 0 && i < c.t.NumPieces() && c.have.Has(i)
}

func (c *Client) bitfield() peer.Bitfield {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(peer.Bitfield(nil), c.have...)
}

// Download fetches every missing piece from peers, verifying each one. It returns
// nil once the torrent is complete and ErrIncomplete if all peers fail first.
func (c *Client) Download(ctx context.Context, peers []string) error {
	missing := make(chan int, c.t.NumPieces())
	for i := range c.t.NumPieces() {
		if !c.hasPiece(i) {
			missing <- i
		}
	}
	if len(missing) == 0 {
		return nil
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, addr := range peers {
		wg.Go(func() {
			if err := c.fetchFrom(wctx, addr, missing); err != nil && wctx.Err() == nil {
				c.log.Info("dropping peer", "peer", addr, "err", err)
			}
		})
	}
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	select {
	case <-c.done:
		cancel()
		<-workersDone
		return nil
	case <-workersDone:
		select {
		case <-c.done:
			return nil
		default:
			return ErrIncomplete
		}
	case <-ctx.Done():
		<-workersDone
		return ctx.Err()
	}
}

// fetchFrom downloads pieces from one peer until the torrent completes or the
// peer fails. A piece the worker cannot finish goes back on missing.
func (c *Client) fetchFrom(ctx context.Context, addr string, missing chan int) error {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := c.tr.Dial(dctx, addr)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	s := &session{
		conn:   conn,
		c:      c,
		has:    peer.NewBitfield(c.t.NumPieces()),
		choked: true,
		msgs:   make(chan *peer.Message),
		errc:   make(chan error, 1),
	}
	if err := s.handshake(); err != nil {
		return err
	}
	quit := make(chan struct{})
	defer close(quit)
	go s.readLoop(quit)
	if err := s.send(&peer.Message{ID: peer.MsgInterested}); err != nil {
		return err
	}

	for {
		var idx int
		select {
		case idx = <-missing:
		case <-c.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
		if !s.has.Has(idx) {
			missing <- idx
			// Give the peer a moment to announce pieces before trying again.
			if _, err := s.read(time.Now().Add(time.Second)); err != nil && !errors.Is(err, errTimeout) {
				return err
			}
			continue
		}
		data, err := s.fetchPiece(idx)
		if err != nil {
			missing <- idx
			return err
		}
		if sha1.Sum(data) != c.t.Pieces[idx] {
			missing <- idx
			return fmt.Errorf("%w: piece %d", ErrBadPiece, idx)
		}
		if err := c.storePiece(idx, data); err != nil {
			missing <- idx
			return err
		}
		c.log.Debug("piece verified", "piece", idx, "peer", addr)
	}
}

func (c *Client) storePiece(idx int, data []byte) error {
	if _, err := c.store.WriteAt(data, int64(idx)*c.t.PieceLength); err != nil {
		return fmt.Errorf("engine: writing piece %d: %w", idx, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.have.Has(idx) {
		return nil
	}
	c.have.Set(idx)
	c.downloaded += int64(len(data))
	if c.have.Count() == c.t.NumPieces() {
		close(c.done)
	}
	return nil
}

var errTimeout = errors.New("engine: timeout")

// session is the downloading side of one peer connection.
type session struct {
	conn   net.Conn
	c      *Client
	has    peer.Bitfield
	choked bool
	msgs   chan *peer.Message
	errc   chan error
}

func (s *session) handshake() error {
	s.conn.SetDeadline(time.Now().Add(ioTimeout))
	defer s.conn.SetDeadline(time.Time{})
	if _, err := (peer.Handshake{InfoHash: s.c.t.InfoHash, PeerID: s.c.peerID}).WriteTo(s.conn); err != nil {
		return err
	}
	h, err := peer.ReadHandshake(s.conn)
	if err != nil {
		return err
	}
	if h.InfoHash != s.c.t.InfoHash {
		return ErrWrongTorrent
	}
	return nil
}

func (s *session) send(m *peer.Message) error {
	s.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	return peer.WriteMessage(s.conn, m)
}

// readLoop reads messages from the peer and hands them to read. Running it on
// its own goroutine means a wait in read never cuts a message in half.
func (s *session) readLoop(quit <-chan struct{}) {
	for {
		s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		m, err := peer.ReadMessage(s.conn, s.c.maxMsg)
		if err != nil {
			s.errc <- err
			return
		}
		select {
		case s.msgs <- m:
		case <-quit:
			return
		}
	}
}

// read returns the next message, or errTimeout at deadline, and applies the
// state the message carries.
func (s *session) read(deadline time.Time) (*peer.Message, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var m *peer.Message
	select {
	case m = <-s.msgs:
	case err := <-s.errc:
		s.errc <- err // keep reporting it
		return nil, err
	case <-timer.C:
		return nil, errTimeout
	}
	if m == nil {
		return nil, nil
	}
	switch m.ID {
	case peer.MsgChoke:
		s.choked = true
	case peer.MsgUnchoke:
		s.choked = false
	case peer.MsgHave:
		i, err := peer.ParseHave(m)
		if err != nil {
			return nil, err
		}
		s.has.Set(int(i))
	case peer.MsgBitfield:
		bf, err := peer.ParseBitfield(m.Payload, s.c.t.NumPieces())
		if err != nil {
			return nil, err
		}
		s.has = bf
	}
	return m, nil
}

// fetchPiece requests every block of piece idx, pipelined, and returns the
// assembled, unverified piece.
func (s *session) fetchPiece(idx int) ([]byte, error) {
	const (
		want = iota
		requested
		received
	)
	size := s.c.t.PieceSize(idx)
	buf := make([]byte, size)
	state := make([]uint8, (size+BlockSize-1)/BlockSize)
	blockLen := func(b int) int64 { return min(BlockSize, size-int64(b)*BlockSize) }
	deadline := time.Now().Add(pieceTimeout)
	got, backlog := 0, 0

	for got < len(state) {
		if !s.choked {
			for b := range state {
				if backlog >= maxBacklog {
					break
				}
				if state[b] == want {
					if err := s.send(peer.Request(peer.MsgRequest, uint32(idx), uint32(b*BlockSize), uint32(blockLen(b)))); err != nil {
						return nil, err
					}
					state[b] = requested
					backlog++
				}
			}
		}

		readBy := time.Now().Add(ioTimeout)
		if deadline.Before(readBy) {
			readBy = deadline
		}
		m, err := s.read(readBy)
		if err != nil {
			return nil, err
		}
		if m == nil {
			continue
		}
		switch m.ID {
		case peer.MsgChoke:
			// A choking peer discards our requests; ask again after unchoke.
			for b := range state {
				if state[b] == requested {
					state[b] = want
				}
			}
			backlog = 0
		case peer.MsgPiece:
			pi, begin, block, err := peer.ParsePiece(m)
			if err != nil {
				return nil, err
			}
			b := int(begin / BlockSize)
			if int(pi) != idx || begin%BlockSize != 0 || b >= len(state) || state[b] != requested || int64(len(block)) != blockLen(b) {
				continue // unsolicited or stale block
			}
			copy(buf[begin:], block)
			state[b] = received
			got++
			backlog--
		}
	}
	return buf, nil
}

// Serve accepts peers on l and uploads verified pieces to them until ctx is done.
func (c *Client) Serve(ctx context.Context, l net.Listener) error {
	defer context.AfterFunc(ctx, func() { l.Close() })()
	sem := make(chan struct{}, maxServeConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // at the connection limit
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			if err := c.serveConn(ctx, conn); err != nil && ctx.Err() == nil {
				c.log.Debug("peer connection closed", "peer", conn.RemoteAddr(), "err", err)
			}
		})
	}
}

func (c *Client) serveConn(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	conn.SetDeadline(time.Now().Add(ioTimeout))
	h, err := peer.ReadHandshake(conn)
	if err != nil {
		return err
	}
	if h.InfoHash != c.t.InfoHash {
		return ErrWrongTorrent
	}
	if _, err := (peer.Handshake{InfoHash: c.t.InfoHash, PeerID: c.peerID}).WriteTo(conn); err != nil {
		return err
	}
	send := func(m *peer.Message) error {
		conn.SetWriteDeadline(time.Now().Add(ioTimeout))
		return peer.WriteMessage(conn, m)
	}
	if err := send(&peer.Message{ID: peer.MsgBitfield, Payload: c.bitfield()}); err != nil {
		return err
	}

	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		m, err := peer.ReadMessage(conn, c.maxMsg)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if m == nil {
			continue
		}
		switch m.ID {
		case peer.MsgInterested:
			if err := send(&peer.Message{ID: peer.MsgUnchoke}); err != nil {
				return err
			}
		case peer.MsgRequest:
			idx, begin, length, err := peer.ParseRequest(m)
			if err != nil {
				return err
			}
			if !c.hasPiece(int(idx)) || length == 0 || length > MaxBlockSize ||
				int64(begin)+int64(length) > c.t.PieceSize(int(idx)) {
				return fmt.Errorf("%w: piece %d [%d, +%d)", ErrBadRequest, idx, begin, length)
			}
			block := make([]byte, length)
			if _, err := c.store.ReadAt(block, int64(idx)*c.t.PieceLength+int64(begin)); err != nil {
				return err
			}
			if err := send(peer.Piece(idx, begin, block)); err != nil {
				return err
			}
			c.mu.Lock()
			c.uploaded += int64(length)
			c.mu.Unlock()
		}
	}
}
