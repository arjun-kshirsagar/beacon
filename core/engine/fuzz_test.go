package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// fuzzTarget is one leeching client per fuzz worker process, fed a fresh
// connection per input.
var fuzzTarget struct {
	once sync.Once
	mem  *transport.Memory
	tor  *torrent.Torrent
	c    *Client
	next atomic.Uint32
}

func setupFuzzTarget(f *testing.F) {
	fuzzTarget.once.Do(func() {
		dir, err := os.MkdirTemp("", "beacon-fuzz-")
		if err != nil {
			f.Fatal(err)
		}
		src := filepath.Join(dir, "src")
		os.MkdirAll(filepath.Join(src, "share"), 0o755)
		os.WriteFile(filepath.Join(src, "share", "data"), bytes.Repeat([]byte("beacon"), 20000), 0o644)
		meta, err := torrent.Create(filepath.Join(src, "share"), 16<<10, "")
		if err != nil {
			f.Fatal(err)
		}
		tor, _ := torrent.Parse(meta)
		store, err := OpenStorage(filepath.Join(dir, "dst"), tor)
		if err != nil {
			f.Fatal(err)
		}
		mem := transport.NewMemory()
		c, err := New(tor, store, Config{Transport: mem, AllowPrivatePeers: true})
		if err != nil {
			f.Fatal(err)
		}
		l, err := mem.Listen("10.0.0.1:6881")
		if err != nil {
			f.Fatal(err)
		}
		go c.Serve(context.Background(), l)
		fuzzTarget.mem, fuzzTarget.tor, fuzzTarget.c = mem, tor, c
	})
}

func encodeMsgs(msgs ...*peer.Message) []byte {
	var b bytes.Buffer
	for _, m := range msgs {
		peer.WriteMessage(&b, m)
	}
	return b.Bytes()
}

// FuzzPeerConn sends arbitrary bytes after a valid handshake and checks that
// the client survives, drops the connection, and leaves no stale state.
func FuzzPeerConn(f *testing.F) {
	setupFuzzTarget(f)
	n := fuzzTarget.tor.NumPieces()
	all := fullBitfield(n)
	eh := peer.ExtHandshake{M: map[string]int{peer.ExtMetadata: 3, peer.ExtPEX: 4}, Port: 7000}
	pex := peer.PEX{Added: []netip.AddrPort{netip.MustParseAddrPort("10.1.2.3:6881")}, Flags: []byte{0}}
	f.Add(encodeMsgs(&peer.Message{ID: peer.MsgBitfield, Payload: all}, &peer.Message{ID: peer.MsgUnchoke},
		peer.Piece(0, 0, make([]byte, BlockSize)), peer.Piece(0, BlockSize, make([]byte, BlockSize))))
	f.Add(encodeMsgs(peer.Extended(peer.ExtHandshakeID, eh.Encode()), &peer.Message{ID: peer.MsgBitfield, Payload: all},
		peer.Extended(pexExtID, pex.Encode()), peer.Extended(metadataExtID, peer.MetadataMsg{Type: peer.MetadataRequest}.Encode())))
	f.Add(encodeMsgs(peer.Have(1), peer.Have(2), &peer.Message{ID: peer.MsgUnchoke}, &peer.Message{ID: peer.MsgChoke},
		&peer.Message{ID: peer.MsgInterested}, peer.Request(peer.MsgRequest, 0, 0, 100), peer.Request(peer.MsgCancel, 0, 0, 100)))
	f.Add([]byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		c, tor := fuzzTarget.c, fuzzTarget.tor
		i := fuzzTarget.next.Add(1)
		ip := fmt.Sprintf("10.%d.%d.%d", 100+i>>16&0x7f, i>>8&0xff, i&0xff)
		conn, err := fuzzTarget.mem.From(ip).Dial(context.Background(), "10.0.0.1:6881")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		peer.Handshake{InfoHash: tor.InfoHash, PeerID: NewPeerID()}.WriteTo(conn)
		if _, err := peer.ReadHandshake(conn); err != nil {
			conn.Close()
			return
		}
		conn.Write(data)
		// Let the client react, draining what it sends so it never blocks on us.
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		buf := make([]byte, 64<<10)
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		conn.Close()

		deadline := time.Now().Add(5 * time.Second)
		for c.Stats().Peers > 0 {
			if time.Now().After(deadline) {
				t.Fatal("connection not released after the peer hung up")
			}
			time.Sleep(time.Millisecond)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		for i, a := range c.pk.avail {
			if a != 0 {
				t.Fatalf("piece %d availability %d with no peers", i, a)
			}
		}
		for i, ap := range c.pk.active {
			for b, blk := range ap.blocks {
				if len(blk.requesters) != 0 {
					t.Fatalf("piece %d block %d still requested from a closed peer", i, b)
				}
			}
		}
		if len(c.queue) > maxQueue {
			t.Fatalf("dial queue grew to %d", len(c.queue))
		}
	})
}
