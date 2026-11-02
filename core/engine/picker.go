package engine

import (
	"crypto/rand"
	"crypto/sha1"
	"math/big"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
)

// maxActiveBytes bounds the memory held by partly downloaded pieces.
const maxActiveBytes = 256 << 20

type blockRef struct{ piece, block int }

type block struct {
	received   bool
	requesters []*peerConn // peers asked for this block and not yet answered
	source     *peerConn   // who delivered it
}

// activePiece is a piece being downloaded into memory.
type activePiece struct {
	buf      []byte
	blocks   []block
	received int
	writing  bool // complete and being verified; no longer accepts blocks
}

// suspect records who sent which version of a block in a piece that failed its
// hash check, so the culprit can be identified once the piece verifies.
type suspect struct {
	key string // ban key of the sender
	sum [20]byte
}

// picker chooses which blocks to request. It is guarded by Client.mu.
type picker struct {
	t         *torrent.Torrent
	have      peer.Bitfield
	avail     []int // how many connected peers have each piece
	active    map[int]*activePiece
	maxActive int
	suspects  map[int][][]suspect // piece → block → senders of failed versions
}

func newPicker(t *torrent.Torrent, have peer.Bitfield) *picker {
	return &picker{
		t:         t,
		have:      have,
		avail:     make([]int, t.NumPieces()),
		active:    make(map[int]*activePiece),
		maxActive: int(max(1, min(64, maxActiveBytes/t.PieceLength))),
		suspects:  make(map[int][][]suspect),
	}
}

func (p *picker) blockLen(piece, b int) int64 {
	return min(BlockSize, p.t.PieceSize(piece)-int64(b)*BlockSize)
}

func (p *picker) missing() int {
	return p.t.NumPieces() - p.have.Count()
}

// pick returns up to n blocks for pc to request, in this order: unrequested
// blocks of pieces already in progress, blocks of a new piece chosen rarest
// first, and finally, in endgame, blocks other peers are already fetching.
func (p *picker) pick(pc *peerConn, n int) []blockRef {
	var out []blockRef
	take := func(i int, ap *activePiece, dup bool) {
		for b := range ap.blocks {
			if len(out) == n {
				return
			}
			blk := &ap.blocks[b]
			if blk.received || pc.outstanding[blockRef{i, b}] {
				continue
			}
			if len(blk.requesters) == 0 || (dup && len(blk.requesters) < 2) {
				out = append(out, blockRef{i, b})
			}
		}
	}

	for i, ap := range p.active {
		if !ap.writing && pc.has.Has(i) {
			take(i, ap, false)
		}
	}
	for len(out) < n && len(p.active) < p.maxActive {
		i := p.rarest(pc)
		if i < 0 {
			break
		}
		ap := &activePiece{
			buf:    make([]byte, p.t.PieceSize(i)),
			blocks: make([]block, (p.t.PieceSize(i)+BlockSize-1)/BlockSize),
		}
		p.active[i] = ap
		take(i, ap, false)
	}
	// Endgame: every missing piece is in flight. Duplicate requests so one slow
	// peer cannot hold up the finish.
	if len(out) == 0 && len(p.active) == p.missing() {
		for i, ap := range p.active {
			if !ap.writing && pc.has.Has(i) {
				take(i, ap, true)
			}
		}
	}
	return out
}

// rarest returns the piece pc has, we lack and nobody is fetching that the
// fewest peers have, breaking ties at random; -1 if there is none.
func (p *picker) rarest(pc *peerConn) int {
	best, ties := -1, 0
	for i := range p.t.NumPieces() {
		if p.have.Has(i) || !pc.has.Has(i) || p.active[i] != nil {
			continue
		}
		switch {
		case best < 0 || p.avail[i] < p.avail[best]:
			best, ties = i, 1
		case p.avail[i] == p.avail[best]:
			ties++
			if r, _ := rand.Int(rand.Reader, big.NewInt(int64(ties))); r.Int64() == 0 {
				best = i
			}
		}
	}
	return best
}

// release forgets every request pc has outstanding.
func (p *picker) release(pc *peerConn) {
	for ref := range pc.outstanding {
		if ap := p.active[ref.piece]; ap != nil {
			blk := &ap.blocks[ref.block]
			blk.requesters = removeConn(blk.requesters, pc)
		}
	}
	clear(pc.outstanding)
}

func removeConn(s []*peerConn, pc *peerConn) []*peerConn {
	for i, x := range s {
		if x == pc {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// received stores a block from pc. It returns the piece if that block completed
// it, and the other peers that were asked for the same block (endgame) so their
// requests can be cancelled. Unrequested blocks are ignored.
func (p *picker) received(pc *peerConn, i int, begin uint32, data []byte) (complete *activePiece, cancel []*peerConn) {
	ap := p.active[i]
	if ap == nil || ap.writing || begin%BlockSize != 0 {
		return nil, nil
	}
	b := int(begin / BlockSize)
	if b >= len(ap.blocks) || int64(len(data)) != p.blockLen(i, b) || !pc.outstanding[blockRef{i, b}] {
		return nil, nil
	}
	blk := &ap.blocks[b]
	for _, other := range blk.requesters {
		delete(other.outstanding, blockRef{i, b})
		if other != pc {
			cancel = append(cancel, other)
		}
	}
	blk.requesters = nil
	if blk.received {
		return nil, cancel
	}
	copy(ap.buf[begin:], data)
	blk.received, blk.source = true, pc
	ap.received++
	if ap.received == len(ap.blocks) {
		ap.writing = true
		return ap, cancel
	}
	return nil, cancel
}

// verified finishes piece i after its hash matched. It returns the ban keys of
// peers that earlier sent blocks differing from the verified data.
func (p *picker) verified(i int, data []byte) []string {
	delete(p.active, i)
	p.have.Set(i)
	var bad []string
	for b, versions := range p.suspects[i] {
		start := int64(b) * BlockSize
		good := sha1.Sum(data[start : start+p.blockLen(i, b)])
		for _, v := range versions {
			if v.sum != good {
				bad = append(bad, v.key)
			}
		}
	}
	delete(p.suspects, i)
	return bad
}

// failed discards piece i after a hash mismatch and records who sent each block.
// It returns the distinct senders.
func (p *picker) failed(i int, ap *activePiece) []string {
	delete(p.active, i)
	if p.suspects[i] == nil {
		p.suspects[i] = make([][]suspect, len(ap.blocks))
	}
	seen := map[string]bool{}
	var senders []string
	for b := range ap.blocks {
		key := ap.blocks[b].source.key
		start := int64(b) * BlockSize
		sum := sha1.Sum(ap.buf[start : start+p.blockLen(i, b)])
		if len(p.suspects[i][b]) < 8 {
			p.suspects[i][b] = append(p.suspects[i][b], suspect{key: key, sum: sum})
		}
		if !seen[key] {
			seen[key] = true
			senders = append(senders, key)
		}
	}
	return senders
}
