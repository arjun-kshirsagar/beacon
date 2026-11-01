package peer

import "fmt"

// Bitfield records which pieces a peer has; the high bit of byte 0 is piece 0.
type Bitfield []byte

// NewBitfield returns an empty bitfield for n pieces.
func NewBitfield(n int) Bitfield { return make(Bitfield, (n+7)/8) }

// ParseBitfield validates a bitfield payload for a torrent of n pieces: it must be
// exactly the right length and its spare trailing bits must be zero.
func ParseBitfield(payload []byte, n int) (Bitfield, error) {
	if n < 0 {
		return nil, fmt.Errorf("%w: negative piece count %d", ErrMalformed, n)
	}
	if len(payload) != (n+7)/8 {
		return nil, fmt.Errorf("%w: bitfield is %d bytes, want %d", ErrMalformed, len(payload), (n+7)/8)
	}
	if spare := n % 8; spare != 0 && payload[len(payload)-1]&(0xff>>spare) != 0 {
		return nil, fmt.Errorf("%w: spare bitfield bits set", ErrMalformed)
	}
	return Bitfield(append([]byte(nil), payload...)), nil
}

// Has reports whether piece i is set. Out-of-range pieces are never set.
func (b Bitfield) Has(i int) bool {
	if i < 0 || i/8 >= len(b) {
		return false
	}
	return b[i/8]>>(7-i%8)&1 == 1
}

// Set marks piece i. Out-of-range pieces are ignored.
func (b Bitfield) Set(i int) {
	if i < 0 || i/8 >= len(b) {
		return
	}
	b[i/8] |= 1 << (7 - i%8)
}

// Count returns the number of set pieces.
func (b Bitfield) Count() int {
	n := 0
	for _, c := range b {
		for ; c != 0; c &= c - 1 {
			n++
		}
	}
	return n
}
