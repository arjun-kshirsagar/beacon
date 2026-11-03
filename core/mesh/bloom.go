package mesh

import (
	"hash/maphash"
	"math"
)

// seen is a duplicate filter: two Bloom filter generations, so the newest
// perGen packets are always remembered and older ones age out. Hashes are
// keyed with a random seed, so peers cannot craft IDs that collide.
type seen struct {
	seed   maphash.Seed
	k      int
	perGen int
	cur    bloom
	prev   bloom
	count  int
}

type bloom []uint64

// newSeen remembers at least perGen packets with a false positive rate of
// about fp per lookup.
func newSeen(perGen int, fp float64) *seen {
	bits := int(math.Ceil(-float64(perGen) * math.Log(fp) / (math.Ln2 * math.Ln2)))
	words := (bits + 63) / 64
	k := max(1, int(math.Round(float64(words*64)/float64(perGen)*math.Ln2)))
	return &seen{seed: maphash.MakeSeed(), k: k, perGen: perGen,
		cur: make(bloom, words), prev: make(bloom, words)}
}

func (s *seen) hashes(key []byte) (uint64, uint64) {
	h := maphash.Bytes(s.seed, key)
	return h, h>>32 | h<<32 | 1 // double hashing; h2 odd so it cycles all bits
}

func (b bloom) has(h1, h2 uint64, k int) bool {
	n := uint64(len(b) * 64)
	for i := range uint64(k) {
		bit := (h1 + i*h2) % n
		if b[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

func (b bloom) add(h1, h2 uint64, k int) {
	n := uint64(len(b) * 64)
	for i := range uint64(k) {
		bit := (h1 + i*h2) % n
		b[bit/64] |= 1 << (bit % 64)
	}
}

// check records key and reports whether it was already seen.
func (s *seen) check(key []byte) bool {
	h1, h2 := s.hashes(key)
	if s.cur.has(h1, h2, s.k) || s.prev.has(h1, h2, s.k) {
		return true
	}
	if s.count >= s.perGen {
		s.prev, s.cur = s.cur, s.prev
		clear(s.cur)
		s.count = 0
	}
	s.cur.add(h1, h2, s.k)
	s.count++
	return false
}
