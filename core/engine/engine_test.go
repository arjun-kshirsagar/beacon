package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// testFiles are sized to straddle piece and block boundaries, with an empty file.
var testFiles = []struct {
	path string
	size int
}{
	{"a.bin", 50_000},
	{"empty", 0},
	{"sub/b.bin", 33_333},
	{"sub/c.bin", 7},
}

const testPieceLength = 32 << 10

// seedDir writes random files under dir/share and returns the parsed torrent.
func seedDir(t *testing.T, dir string) *torrent.Torrent {
	t.Helper()
	root := filepath.Join(dir, "share")
	for _, f := range testFiles {
		p := filepath.Join(root, f.path)
		os.MkdirAll(filepath.Dir(p), 0o755)
		data := make([]byte, f.size)
		rand.Read(data)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := torrent.Create(root, testPieceLength, "")
	if err != nil {
		t.Fatal(err)
	}
	tor, err := torrent.Parse(meta)
	if err != nil {
		t.Fatal(err)
	}
	return tor
}

func newClient(t *testing.T, tor *torrent.Torrent, dir string, tr transport.Transport) *Client {
	t.Helper()
	store, err := OpenStorage(dir, tor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	c, err := New(tor, store, Config{Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serve starts c seeding on addr until the test ends.
func serve(t *testing.T, c *Client, tr transport.Transport, addr string) {
	t.Helper()
	l, err := tr.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Serve(ctx, l)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func sameFiles(t *testing.T, a, b string) {
	t.Helper()
	for _, f := range testFiles {
		x, err1 := os.ReadFile(filepath.Join(a, "share", f.path))
		y, err2 := os.ReadFile(filepath.Join(b, "share", f.path))
		if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
			t.Errorf("%s differs (%v, %v)", f.path, err1, err2)
		}
	}
}

func TestStorageAcrossFiles(t *testing.T) {
	src := t.TempDir()
	tor := seedDir(t, src)
	s, err := OpenStorage(src, tor)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a, _ := os.ReadFile(filepath.Join(src, "share", "a.bin"))
	b, _ := os.ReadFile(filepath.Join(src, "share", "sub", "b.bin"))
	want := append(a[len(a)-10:], b[:10]...)
	got := make([]byte, 20)
	if _, err := s.ReadAt(got, int64(len(a)-10)); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadAt across files: %v", err)
	}
	if _, err := s.ReadAt(make([]byte, 2), tor.Length-1); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read past end: %v", err)
	}

	have, err := Verify(tor, s)
	if err != nil || have.Count() != tor.NumPieces() {
		t.Fatalf("Verify: %d/%d pieces, %v", have.Count(), tor.NumPieces(), err)
	}
	// Corrupt one byte in the middle of the data: exactly one piece fails.
	if _, err := s.WriteAt([]byte{^a[40_000]}, 40_000); err != nil {
		t.Fatal(err)
	}
	have, _ = Verify(tor, s)
	if have.Count() != tor.NumPieces()-1 || have.Has(1) {
		t.Fatalf("after corruption: %08b", have)
	}
}

func TestDownloadFromTwoSeeders(t *testing.T) {
	net := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, net), net, "seed1")
	serve(t, newClient(t, tor, src, net), net, "seed2")

	dst := t.TempDir()
	c := newClient(t, tor, dst, net)
	if st := c.Stats(); st.Pieces != 0 || st.Left != tor.Length {
		t.Fatalf("fresh download stats %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Download(ctx, []string{"seed1", "seed2", "nobody"}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)
	if st := c.Stats(); st.Pieces != tor.NumPieces() || st.Left != 0 || st.Downloaded != tor.Length {
		t.Fatalf("final stats %+v", st)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done not closed")
	}
}

func TestResume(t *testing.T) {
	net := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, net), net, "seed")

	// Pre-populate the destination with a.bin, which covers the first piece.
	dst := t.TempDir()
	os.MkdirAll(filepath.Join(dst, "share"), 0o755)
	a, _ := os.ReadFile(filepath.Join(src, "share", "a.bin"))
	os.WriteFile(filepath.Join(dst, "share", "a.bin"), a, 0o644)

	c := newClient(t, tor, dst, net)
	if st := c.Stats(); st.Pieces != 1 {
		t.Fatalf("resumed with %d pieces, want 1", st.Pieces)
	}
	if err := c.Download(context.Background(), []string{"seed"}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)
	if st := c.Stats(); st.Downloaded != tor.Length-tor.PieceLength {
		t.Fatalf("downloaded %d bytes, want %d", st.Downloaded, tor.Length-tor.PieceLength)
	}
}

// poisoner claims every piece and answers every request with garbage.
func poisoner(t *testing.T, tr transport.Transport, addr string, tor *torrent.Torrent) {
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
				peer.ReadHandshake(conn)
				peer.Handshake{InfoHash: tor.InfoHash}.WriteTo(conn)
				all := peer.NewBitfield(tor.NumPieces())
				for i := range tor.NumPieces() {
					all.Set(i)
				}
				peer.WriteMessage(conn, &peer.Message{ID: peer.MsgBitfield, Payload: all})
				peer.WriteMessage(conn, &peer.Message{ID: peer.MsgUnchoke})
				for {
					m, err := peer.ReadMessage(conn, 1<<20)
					if err != nil {
						return
					}
					if m != nil && m.ID == peer.MsgRequest {
						idx, begin, length, _ := peer.ParseRequest(m)
						junk := make([]byte, length)
						rand.Read(junk)
						peer.WriteMessage(conn, peer.Piece(idx, begin, junk))
					}
				}
			}()
		}
	}()
}

func TestPoisonedPeerIsDropped(t *testing.T) {
	net := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	poisoner(t, net, "evil", tor)
	serve(t, newClient(t, tor, src, net), net, "honest")

	dst := t.TempDir()
	c := newClient(t, tor, dst, net)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Download(ctx, []string{"evil", "honest"}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)

	// With only the poisoner, nothing bad is ever written and the download fails.
	dst2 := t.TempDir()
	c2 := newClient(t, tor, dst2, net)
	if err := c2.Download(ctx, []string{"evil"}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("poisoner only: got %v, want ErrIncomplete", err)
	}
	if st := c2.Stats(); st.Pieces != 0 {
		t.Fatalf("stored %d poisoned pieces", st.Pieces)
	}
}

// dialSeeder handshakes with a seeder and consumes its bitfield.
func dialSeeder(t *testing.T, tr transport.Transport, addr string, infoHash [20]byte) net.Conn {
	t.Helper()
	conn, err := tr.Dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	peer.Handshake{InfoHash: infoHash}.WriteTo(conn)
	if _, err := peer.ReadHandshake(conn); err != nil {
		t.Fatal(err)
	}
	if m, err := peer.ReadMessage(conn, 1<<20); err != nil || m.ID != peer.MsgBitfield {
		t.Fatalf("expected bitfield, got %v, %v", m, err)
	}
	return conn
}

func TestServeRejectsBadRequests(t *testing.T) {
	src := t.TempDir()
	tor := seedDir(t, src)
	tests := []struct {
		name string
		req  *peer.Message
	}{
		{"piece out of range", peer.Request(peer.MsgRequest, uint32(tor.NumPieces()), 0, BlockSize)},
		{"past end of piece", peer.Request(peer.MsgRequest, 0, uint32(tor.PieceLength-10), 20)},
		{"oversized block", peer.Request(peer.MsgRequest, 0, 0, MaxBlockSize+1)},
		{"zero length", peer.Request(peer.MsgRequest, 0, 0, 0)},
		{"offset overflow", peer.Request(peer.MsgRequest, 0, 0xffffffff, 16)},
		{"malformed", &peer.Message{ID: peer.MsgRequest, Payload: []byte{1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net := transport.NewMemory()
			serve(t, newClient(t, tor, src, net), net, "seed")
			conn := dialSeeder(t, net, "seed", tor.InfoHash)
			peer.WriteMessage(conn, tt.req)
			// The seeder must hang up without sending data.
			if m, err := peer.ReadMessage(conn, 1<<20); err == nil {
				t.Fatalf("seeder answered with %v", m.ID)
			}
		})
	}

	t.Run("valid request is served", func(t *testing.T) {
		net := transport.NewMemory()
		serve(t, newClient(t, tor, src, net), net, "seed")
		conn := dialSeeder(t, net, "seed", tor.InfoHash)
		peer.WriteMessage(conn, &peer.Message{ID: peer.MsgInterested})
		peer.WriteMessage(conn, peer.Request(peer.MsgRequest, 0, 0, 100))
		m, err := peer.ReadMessage(conn, 1<<20)
		if err != nil || m.ID != peer.MsgUnchoke {
			t.Fatalf("want unchoke, got %v %v", m, err)
		}
		m, err = peer.ReadMessage(conn, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		_, _, block, err := peer.ParsePiece(m)
		a, _ := os.ReadFile(filepath.Join(src, "share", "a.bin"))
		if err != nil || !bytes.Equal(block, a[:100]) {
			t.Fatalf("wrong block: %v", err)
		}
	})
}

func TestWrongInfoHash(t *testing.T) {
	net := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, net), net, "seed")

	conn, _ := net.Dial(context.Background(), "seed")
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	peer.Handshake{InfoHash: [20]byte{1}}.WriteTo(conn)
	if _, err := peer.ReadHandshake(conn); err == nil {
		t.Fatal("seeder handshook for an unknown torrent")
	}
}

func mkdirWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
