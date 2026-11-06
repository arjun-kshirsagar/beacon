package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
)

// Bounds that keep every attack small: enough to show a defense working, not
// enough to matter anywhere else.
const (
	maxFloodConns = 64
	maxFloodMsgs  = 5000
	ioTimeout     = 30 * time.Second
)

func loadTorrent(path string) (*torrent.Torrent, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return torrent.Parse(b)
}

func peerID() [20]byte {
	var id [20]byte
	copy(id[:], "-AT0001-")
	rand.Read(id[8:])
	return id
}

// serve accepts BitTorrent connections on a lab address until ctx ends,
// handing each one, after the handshake, to handle.
func serve(ctx context.Context, listen string, ih [20]byte, ext bool, handle func(net.Conn)) error {
	if err := labListen(listen); err != nil {
		return err
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer context.AfterFunc(ctx, func() { l.Close() })()
	slog.Info("listening", "addr", l.Addr())
	for {
		c, err := l.Accept()
		if err != nil {
			return nil
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(ioTimeout))
			h, err := peer.ReadHandshake(c)
			if err != nil || h.InfoHash != ih {
				return
			}
			out := peer.Handshake{InfoHash: ih, PeerID: peerID()}
			if ext {
				out.SetExtensions()
			}
			if _, err := out.WriteTo(c); err != nil {
				return
			}
			handle(c)
		}()
	}
}

// cmdPoison is a seeder that claims every piece and answers every request
// with random bytes. The defense: the victim checks each piece's SHA-1, bans
// the only sender of a bad piece (and, with several senders, finds the
// culprit once the piece verifies), and completes from honest peers.
func cmdPoison(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("poison", flag.ContinueOnError)
	tpath := fs.String("torrent", "", "the .torrent to pretend to seed")
	listen := fs.String("listen", ":6881", "address to accept victims on")
	if err := fs.Parse(args); err != nil || *tpath == "" {
		return errors.New("usage: attacker poison -torrent <file> [-listen addr]")
	}
	t, err := loadTorrent(*tpath)
	if err != nil {
		return err
	}
	var served atomic.Int64
	defer func() { slog.Info("poison done", "bad blocks served", served.Load()) }()
	return serve(ctx, *listen, t.InfoHash, false, func(c net.Conn) {
		all := peer.NewBitfield(t.NumPieces())
		for i := range t.NumPieces() {
			all.Set(i)
		}
		peer.WriteMessage(c, &peer.Message{ID: peer.MsgBitfield, Payload: all})
		peer.WriteMessage(c, &peer.Message{ID: peer.MsgUnchoke})
		for {
			c.SetDeadline(time.Now().Add(ioTimeout))
			m, err := peer.ReadMessage(c, 1<<20)
			if err != nil {
				slog.Info("victim hung up", "peer", c.RemoteAddr(), "err", err)
				return
			}
			if m == nil || m.ID != peer.MsgRequest || len(m.Payload) != 12 {
				continue
			}
			idx, begin, length := be32(m.Payload), be32(m.Payload[4:]), be32(m.Payload[8:])
			if length > 1<<17 {
				continue
			}
			junk := make([]byte, length)
			rand.Read(junk)
			if peer.WriteMessage(c, peer.Piece(idx, begin, junk)) != nil {
				return
			}
			served.Add(1)
		}
	})
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// cmdFlood opens more connections than one address is allowed and floods
// each with control messages. The defense: a per-IP connection limit, a
// per-connection message rate limit that disconnects and penalises the
// sender, and reputation bans that refuse it afterwards. Honest peers keep
// downloading throughout.
func cmdFlood(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("flood", flag.ContinueOnError)
	tpath := fs.String("torrent", "", "the .torrent the victim serves")
	to := fs.String("target", "", "victim host:port")
	conns := fs.Int("conns", 16, fmt.Sprintf("connections to open (at most %d)", maxFloodConns))
	msgs := fs.Int("msgs", 2000, fmt.Sprintf("messages per connection (at most %d)", maxFloodMsgs))
	if err := fs.Parse(args); err != nil || *tpath == "" || *to == "" {
		return errors.New("usage: attacker flood -torrent <file> -target host:port [-conns n] [-msgs n]")
	}
	t, err := loadTorrent(*tpath)
	if err != nil {
		return err
	}
	addr, err := target(*to)
	if err != nil {
		return err
	}
	n, per := min(*conns, maxFloodConns), min(*msgs, maxFloodMsgs)
	var refused, cut, survived atomic.Int64
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			d := net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, "tcp", addr.String())
			if err != nil {
				refused.Add(1)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(ioTimeout))
			peer.Handshake{InfoHash: t.InfoHash, PeerID: peerID()}.WriteTo(c)
			if _, err := peer.ReadHandshake(c); err != nil {
				refused.Add(1) // turned away at once: limit or ban
				return
			}
			go io.Copy(io.Discard, c)
			for range per {
				if peer.WriteMessage(c, &peer.Message{ID: peer.MsgInterested}) != nil {
					cut.Add(1) // disconnected mid-flood
					return
				}
			}
			survived.Add(1)
		})
	}
	wg.Wait()
	slog.Info("flood done", "connections", n, "messages each", per,
		"refused", refused.Load(), "cut off", cut.Load(), "survived", survived.Load())
	return nil
}

// cmdBadMeta answers metadata requests (BEP 9) with the wrong info
// dictionary: random bytes of the advertised size, or with -oversize a size
// past the limit. The defense: a magnet download checks the metadata against
// the info-hash before using it and refuses oversized metadata, then gets
// the real metadata from an honest peer.
func cmdBadMeta(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("badmeta", flag.ContinueOnError)
	tpath := fs.String("torrent", "", "the .torrent whose info-hash to answer for")
	listen := fs.String("listen", ":6881", "address to accept victims on")
	oversize := fs.Bool("oversize", false, "advertise metadata larger than clients accept")
	if err := fs.Parse(args); err != nil || *tpath == "" {
		return errors.New("usage: attacker badmeta -torrent <file> [-listen addr] [-oversize]")
	}
	t, err := loadTorrent(*tpath)
	if err != nil {
		return err
	}
	size := len(t.InfoBytes)
	if *oversize {
		size = peer.MaxMetadataSize + 1
	}
	const ourID = 3
	return serve(ctx, *listen, t.InfoHash, true, func(c net.Conn) {
		eh := peer.ExtHandshake{M: map[string]int{peer.ExtMetadata: ourID}, MetadataSize: size}
		peer.WriteMessage(c, peer.Extended(peer.ExtHandshakeID, eh.Encode()))
		theirID := 0
		for {
			c.SetDeadline(time.Now().Add(ioTimeout))
			m, err := peer.ReadMessage(c, 1<<20)
			if err != nil {
				slog.Info("victim hung up", "peer", c.RemoteAddr(), "err", err)
				return
			}
			if m == nil || m.ID != peer.MsgExtended {
				continue
			}
			id, body, err := peer.ParseExtended(m)
			if err != nil {
				return
			}
			if id == peer.ExtHandshakeID {
				if h, err := peer.ParseExtHandshake(body); err == nil {
					theirID = h.M[peer.ExtMetadata]
				}
				continue
			}
			req, err := peer.ParseMetadataMsg(body)
			if err != nil || req.Type != peer.MetadataRequest || theirID == 0 {
				continue
			}
			n := min(peer.MetadataPieceSize, size-req.Piece*peer.MetadataPieceSize)
			if n <= 0 {
				continue
			}
			junk := make([]byte, n)
			rand.Read(junk)
			msg := peer.MetadataMsg{Type: peer.MetadataData, Piece: req.Piece, TotalSize: size, Data: junk}
			if peer.WriteMessage(c, peer.Extended(uint8(theirID), msg.Encode())) != nil {
				return
			}
			slog.Info("served bad metadata", "piece", req.Piece)
		}
	})
}
