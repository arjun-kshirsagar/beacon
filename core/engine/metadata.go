package engine

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const (
	metadataWorkers = 24
	metadataTimeout = 20 * time.Second
	metadataMaxMsg  = 1 << 21
)

var (
	// ErrNoMetadata reports that no peer delivered the info dictionary.
	ErrNoMetadata = errors.New("engine: no peer delivered the torrent metadata")
	// ErrBadMetadata reports metadata whose hash does not match the info-hash.
	ErrBadMetadata = errors.New("engine: metadata does not match info-hash")
)

// FetchMetadata downloads the info dictionary for infoHash from peers using the
// metadata extension (BEP 9), trying several peers at once, and returns it once
// its SHA-1 matches. It gives up with ErrNoMetadata when peers is closed and every
// peer has failed.
func FetchMetadata(ctx context.Context, tr transport.Transport, infoHash [20]byte, peers <-chan string, log *slog.Logger) ([]byte, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	peerID := NewPeerID()
	result := make(chan []byte, 1)
	sem := make(chan struct{}, metadataWorkers)
	var wg sync.WaitGroup
	defer wg.Wait()
	tried := map[string]bool{}

	for open := true; open; {
		select {
		case info := <-result:
			return info, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case addr, ok := <-peers:
			if !ok {
				open = false
				break
			}
			if tried[addr] {
				continue
			}
			tried[addr] = true
			wg.Go(func() {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				info, err := fetchMetadataFrom(ctx, tr, addr, infoHash, peerID)
				if err != nil {
					if ctx.Err() == nil {
						log.Debug("metadata fetch failed", "peer", addr, "err", err)
					}
					return
				}
				select {
				case result <- info:
				default:
				}
			})
		}
	}

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	select {
	case info := <-result:
		return info, nil
	case <-allDone:
		select {
		case info := <-result:
			return info, nil
		default:
			return nil, ErrNoMetadata
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func fetchMetadataFrom(ctx context.Context, tr transport.Transport, addr string, infoHash, peerID [20]byte) ([]byte, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := tr.Dial(dctx, addr)
	cancel()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	conn.SetDeadline(time.Now().Add(metadataTimeout))

	ours := peer.Handshake{InfoHash: infoHash, PeerID: peerID}
	ours.SetExtensions()
	if _, err := ours.WriteTo(conn); err != nil {
		return nil, err
	}
	theirs, err := peer.ReadHandshake(conn)
	if err != nil {
		return nil, err
	}
	if theirs.InfoHash != infoHash {
		return nil, ErrWrongTorrent
	}
	if !theirs.SupportsExtensions() {
		return nil, errors.New("engine: peer does not support extensions")
	}
	eh := peer.ExtHandshake{M: map[string]int{peer.ExtMetadata: metadataExtID}, Version: clientVersion}
	if err := peer.WriteMessage(conn, peer.Extended(peer.ExtHandshakeID, eh.Encode())); err != nil {
		return nil, err
	}

	var size, theirID int
	for theirID == 0 {
		m, err := peer.ReadMessage(conn, metadataMaxMsg)
		if err != nil {
			return nil, err
		}
		if m == nil || m.ID != peer.MsgExtended {
			continue
		}
		id, body, err := peer.ParseExtended(m)
		if err != nil || id != peer.ExtHandshakeID {
			continue
		}
		h, err := peer.ParseExtHandshake(body)
		if err != nil {
			return nil, err
		}
		theirID, size = h.M[peer.ExtMetadata], h.MetadataSize
		if theirID == 0 || size == 0 {
			return nil, errors.New("engine: peer cannot serve metadata")
		}
	}

	n := (size + peer.MetadataPieceSize - 1) / peer.MetadataPieceSize
	for i := range n {
		req := peer.MetadataMsg{Type: peer.MetadataRequest, Piece: i}
		if err := peer.WriteMessage(conn, peer.Extended(uint8(theirID), req.Encode())); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, size)
	got := make([]bool, n)
	for left := n; left > 0; {
		m, err := peer.ReadMessage(conn, metadataMaxMsg)
		if err != nil {
			return nil, err
		}
		if m == nil || m.ID != peer.MsgExtended {
			continue
		}
		id, body, err := peer.ParseExtended(m)
		if err != nil || id != metadataExtID {
			continue
		}
		mm, err := peer.ParseMetadataMsg(body)
		if err != nil {
			return nil, err
		}
		switch {
		case mm.Type == peer.MetadataReject:
			return nil, fmt.Errorf("engine: peer rejected metadata piece %d", mm.Piece)
		case mm.Type != peer.MetadataData || mm.Piece >= n || got[mm.Piece]:
			continue
		}
		start := mm.Piece * peer.MetadataPieceSize
		if mm.TotalSize != size || len(mm.Data) != min(peer.MetadataPieceSize, size-start) {
			return nil, fmt.Errorf("%w: metadata piece %d has the wrong size", peer.ErrMalformed, mm.Piece)
		}
		copy(buf[start:], mm.Data)
		got[mm.Piece] = true
		left--
	}
	if sha1.Sum(buf) != infoHash {
		return nil, ErrBadMetadata
	}
	return buf, nil
}
