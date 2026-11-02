package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// fakeConn returns a peerConn for picker and choker unit tests.
func fakeConn(c *Client, key string, has peer.Bitfield) *peerConn {
	a, b := net.Pipe()
	b.Close()
	return &peerConn{
		c: c, conn: a, key: key, has: has, amChoking: true, peerChoking: true,
		ctrl: make(chan *peer.Message, ctrlQueue), closed: make(chan struct{}),
		outstanding: make(map[blockRef]bool),
	}
}

func fullBitfield(n int) peer.Bitfield {
	bf := peer.NewBitfield(n)
	for i := range n {
		bf.Set(i)
	}
	return bf
}

func TestRarestFirst(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	n := tor.NumPieces()
	for i := range n {
		c.pk.avail[i] = 5
	}
	c.pk.avail[2] = 1 // the rarest piece
	pc := fakeConn(c, "a", fullBitfield(n))

	refs := c.pk.pick(pc, 1)
	if len(refs) != 1 || refs[0] != (blockRef{2, 0}) {
		t.Fatalf("picked %v, want the first block of rare piece 2", refs)
	}
	// Once a piece is in progress, its remaining blocks come before new pieces.
	pc.outstanding[refs[0]] = true
	c.pk.active[2].blocks[0].requesters = []*peerConn{pc}
	refs = c.pk.pick(pc, 1)
	if refs[0] != (blockRef{2, 1}) {
		t.Fatalf("picked %v, want piece 2 block 1", refs)
	}
	// A peer without piece 2 starts a different piece.
	other := peer.NewBitfield(n)
	other.Set(0)
	if refs := c.pk.pick(fakeConn(c, "b", other), 1); refs[0].piece != 0 {
		t.Fatalf("picked %v for a peer that only has piece 0", refs)
	}
}

func TestEndgameDuplicatesRequests(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	n := tor.NumPieces()
	slow := fakeConn(c, "slow", fullBitfield(n))
	fast := fakeConn(c, "fast", fullBitfield(n))

	// The slow peer takes every block of every piece.
	for {
		refs := c.pk.pick(slow, maxBacklog)
		if len(refs) == 0 {
			break
		}
		for _, r := range refs {
			slow.outstanding[r] = true
			c.pk.active[r.piece].blocks[r.block].requesters = append(c.pk.active[r.piece].blocks[r.block].requesters, slow)
		}
	}
	refs := c.pk.pick(fast, maxBacklog)
	if len(refs) == 0 {
		t.Fatal("no endgame requests for the fast peer")
	}
	for _, r := range refs {
		fast.outstanding[r] = true
		c.pk.active[r.piece].blocks[r.block].requesters = append(c.pk.active[r.piece].blocks[r.block].requesters, fast)
	}
	// The fast peer's delivery cancels the slow peer's duplicate request.
	r := refs[0]
	_, cancels := c.pk.received(fast, r.piece, uint32(r.block*BlockSize), make([]byte, c.pk.blockLen(r.piece, r.block)))
	if len(cancels) != 1 || cancels[0] != slow || slow.outstanding[r] {
		t.Fatalf("cancels = %v, slow still outstanding = %v", cancels, slow.outstanding[r])
	}
}

func TestRechoke(t *testing.T) {
	tor := seedDir(t, t.TempDir())
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	var pcs []*peerConn
	for i := range 8 {
		pc := fakeConn(c, fmt.Sprint(i), peer.NewBitfield(tor.NumPieces()))
		pc.peerInterested = i < 6
		pc.rateDown = int64(i * 100)
		c.conns[pc] = true
		pcs = append(pcs, pc)
	}
	c.rechoke(true)
	unchoked := 0
	for i, pc := range pcs {
		if !pc.amChoking {
			unchoked++
			if !pc.peerInterested {
				t.Errorf("uninterested peer %d unchoked", i)
			}
		}
	}
	if unchoked != uploadSlots {
		t.Fatalf("%d peers unchoked, want %d", unchoked, uploadSlots)
	}
	// The best uploaders among interested peers (5, 4, 3) are always unchoked.
	for _, i := range []int{5, 4, 3} {
		if pcs[i].amChoking {
			t.Errorf("top uploader %d choked", i)
		}
	}
}

func TestSmartBan(t *testing.T) {
	src := t.TempDir()
	tor := seedDir(t, src)
	srcStore, err := OpenStorage(src, tor)
	if err != nil {
		t.Fatal(err)
	}
	defer srcStore.Close()
	c := newClient(t, tor, t.TempDir(), transport.NewMemory())
	good := fakeConn(c, "good", fullBitfield(tor.NumPieces()))
	evil := fakeConn(c, "evil", fullBitfield(tor.NumPieces()))
	c.conns[good], c.conns[evil] = true, true

	// Piece 0 assembled with block 1 from the evil peer fails...
	want := make([]byte, tor.PieceSize(0))
	srcStore.ReadAt(want, 0)
	data := bytes.Clone(want)
	data[BlockSize] ^= 0xff
	ap := &activePiece{buf: data, blocks: make([]block, 2)}
	ap.blocks[0].source, ap.blocks[1].source = good, evil
	c.mu.Lock()
	c.pk.active[0] = ap
	c.mu.Unlock()
	c.pieceDone(0, ap)
	if c.rep.Banned("good") || c.rep.Banned("evil") {
		t.Fatal("banned before the culprit is known")
	}
	// ...then verifies with good data, which identifies the evil block.
	ap = &activePiece{buf: bytes.Clone(want), blocks: make([]block, 2)}
	ap.blocks[0].source, ap.blocks[1].source = good, good
	c.mu.Lock()
	c.pk.active[0] = ap
	c.mu.Unlock()
	c.pieceDone(0, ap)
	if !c.rep.Banned("evil") || c.rep.Banned("good") {
		t.Fatalf("evil banned=%v, good banned=%v", c.rep.Banned("evil"), c.rep.Banned("good"))
	}
}

// staller claims every piece, unchokes, and never answers a request.
func staller(t *testing.T, tr transport.Transport, addr string, tor *torrent.Torrent) {
	t.Helper()
	l, err := tr.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := peer.ReadHandshake(conn); err != nil {
					return // plaintext-only peers hang up on MSE
				}
				peer.Handshake{InfoHash: tor.InfoHash, PeerID: NewPeerID()}.WriteTo(conn)
				peer.WriteMessage(conn, &peer.Message{ID: peer.MsgBitfield, Payload: fullBitfield(tor.NumPieces())})
				peer.WriteMessage(conn, &peer.Message{ID: peer.MsgUnchoke})
				for {
					if _, err := peer.ReadMessage(conn, 1<<20); err != nil {
						return
					}
				}
			}()
		}
	}()
}

func TestEndgameBeatsStalledPeer(t *testing.T) {
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	staller(t, mem, "10.0.0.66:6881", tor)
	serve(t, newClient(t, tor, src, mem), mem, "10.0.0.1:6881")

	dst := t.TempDir()
	c := newClient(t, tor, dst, mem)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // well under snubTimeout
	defer cancel()
	if err := c.Download(ctx, []string{"10.0.0.66:6881", "10.0.0.1:6881"}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)
}

func TestSwarm(t *testing.T) {
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, mem), mem, "10.0.0.1:6881")

	// Three leechers that know the seeder and each other.
	addrs := []string{"10.0.0.1:6881", "10.0.0.2:6881", "10.0.0.3:6881", "10.0.0.4:6881"}
	var leechers []*Client
	var dirs []string
	for i := 1; i < len(addrs); i++ {
		dir := t.TempDir()
		c := newClient(t, tor, dir, mem)
		serve(t, c, mem, addrs[i])
		leechers = append(leechers, c)
		dirs = append(dirs, dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errs := make(chan error, len(leechers))
	for i, c := range leechers {
		var others []string
		for j, a := range addrs {
			if j != i+1 {
				others = append(others, a)
			}
		}
		go func() { errs <- c.Download(ctx, others) }()
	}
	for range leechers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range dirs {
		sameFiles(t, src, d)
	}
}

func TestFetchMetadata(t *testing.T) {
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, mem), mem, "10.0.0.1:6881")

	// A liar on the same info-hash serves a different (valid-looking) info dict.
	liarDir := t.TempDir()
	liarTor := seedDir(t, liarDir)
	liarTor.InfoHash = tor.InfoHash
	serve(t, newClient(t, liarTor, liarDir, mem), mem, "10.0.0.66:6881")

	peers := make(chan string, 3)
	peers <- "10.0.0.66:6881"
	peers <- "10.0.0.1:6881"
	peers <- "10.0.0.99:6881" // nobody there
	close(peers)
	info, err := FetchMetadata(context.Background(), mem, tor.InfoHash, peers, EncryptPrefer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info, tor.InfoBytes) {
		t.Fatal("metadata differs from the torrent's info dictionary")
	}

	got, err := torrent.FromInfo(info, nil)
	if err != nil || got.InfoHash != tor.InfoHash {
		t.Fatalf("FromInfo: %v", err)
	}

	only := make(chan string, 1)
	only <- "10.0.0.66:6881"
	close(only)
	if _, err := FetchMetadata(context.Background(), mem, tor.InfoHash, only, EncryptPrefer, nil); !errors.Is(err, ErrNoMetadata) {
		t.Fatalf("liar only: got %v", err)
	}
}

func TestMetadataLargerThanOnePiece(t *testing.T) {
	// Many files make an info dictionary bigger than one 16 KiB metadata piece.
	dir := t.TempDir()
	root := dir + "/many"
	for i := range 600 {
		writeFile(t, fmt.Sprintf("%s/file-with-a-fairly-long-name-%04d.txt", root, i), 10)
	}
	meta, err := torrent.Create(root, 16<<10, "")
	if err != nil {
		t.Fatal(err)
	}
	tor, _ := torrent.Parse(meta)
	if len(tor.InfoBytes) <= peer.MetadataPieceSize {
		t.Fatalf("info is only %d bytes", len(tor.InfoBytes))
	}
	mem := transport.NewMemory()
	serve(t, newClient(t, tor, dir, mem), mem, "10.0.0.1:6881")
	peers := make(chan string, 1)
	peers <- "10.0.0.1:6881"
	close(peers)
	info, err := FetchMetadata(context.Background(), mem, tor.InfoHash, peers, EncryptPrefer, nil)
	if err != nil || !bytes.Equal(info, tor.InfoBytes) {
		t.Fatalf("fetch: %v", err)
	}
}

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	if err := mkdirWrite(path, data); err != nil {
		t.Fatal(err)
	}
}
