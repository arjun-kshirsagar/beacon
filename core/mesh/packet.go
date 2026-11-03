package mesh

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Wire constants; see docs/protocol-spec.md.
const (
	// Version is the protocol version byte every packet starts with.
	Version = 1
	// MaxTTL is the most hops a packet may travel.
	MaxTTL = 7
	// MaxPayload bounds a packet's payload.
	MaxPayload = 4096
	// MaxPacket bounds a whole encoded packet.
	MaxPacket = headerSize + IDSize + 2 + MaxPayload + ed25519.SignatureSize

	// IDSize is the size of packet and peer IDs.
	IDSize     = 8
	headerSize = 4 + IDSize + 8 + IDSize // version, type, ttl, flags, packet ID, time, sender

	flagRecipient = 0x01
	flagSigned    = 0x02
	knownFlags    = flagRecipient | flagSigned
)

// Type says what a packet carries.
type Type uint8

// Packet types.
const (
	TypeAnnounce  Type = 0x01 // identity and keys; broadcast, signed
	TypeChannel   Type = 0x02 // public channel message; broadcast, signed
	TypeHandshake Type = 0x03 // Noise XX handshake message; directed
	TypeEncrypted Type = 0x04 // Noise transport message; directed
	TypeShare     Type = 0x05 // a file offered to the mesh; broadcast, signed
)

func (t Type) String() string {
	switch t {
	case TypeAnnounce:
		return "announce"
	case TypeChannel:
		return "channel"
	case TypeHandshake:
		return "handshake"
	case TypeEncrypted:
		return "encrypted"
	case TypeShare:
		return "share"
	}
	return fmt.Sprintf("type(%#x)", uint8(t))
}

func (t Type) valid() bool { return t >= TypeAnnounce && t <= TypeShare }

// signed reports whether packets of type t must carry a signature, and
// directed whether they must carry a recipient.
func (t Type) signed() bool   { return t == TypeAnnounce || t == TypeChannel || t == TypeShare }
func (t Type) directed() bool { return t == TypeHandshake || t == TypeEncrypted }

// PeerID is a node's ephemeral, rotating mesh address.
type PeerID [IDSize]byte

// PacketID identifies one packet for deduplication.
type PacketID [IDSize]byte

// ErrMalformed reports a packet that does not follow the wire format.
var ErrMalformed = errors.New("mesh: malformed packet")

// Packet is one mesh packet.
type Packet struct {
	Type      Type
	TTL       uint8
	ID        PacketID
	Time      time.Time // creation time, millisecond precision
	Sender    PeerID
	Recipient *PeerID // nil for broadcasts
	Payload   []byte
	Signature []byte // Ed25519, for signed types
}

// Encode returns the wire form of p.
func (p *Packet) Encode() []byte {
	b := p.appendBody(make([]byte, 0, p.size()))
	return append(b, p.Signature...)
}

func (p *Packet) size() int {
	n := headerSize + 2 + len(p.Payload) + len(p.Signature)
	if p.Recipient != nil {
		n += IDSize
	}
	return n
}

// appendBody appends everything but the signature.
func (p *Packet) appendBody(b []byte) []byte {
	var flags byte
	if p.Recipient != nil {
		flags |= flagRecipient
	}
	if p.Signature != nil {
		flags |= flagSigned
	}
	b = append(b, Version, byte(p.Type), p.TTL, flags)
	b = append(b, p.ID[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(p.Time.UnixMilli()))
	b = append(b, p.Sender[:]...)
	if p.Recipient != nil {
		b = append(b, p.Recipient[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.Payload)))
	return append(b, p.Payload...)
}

// signedBytes is what the signature covers: a context string and the body with
// the TTL zeroed, since relays change the TTL. The signed flag is set, so a
// signature cannot be moved to an unsigned packet or stripped.
func (p *Packet) signedBytes() []byte {
	q := *p
	q.TTL = 0
	q.Signature = []byte{}
	return q.appendBody([]byte("beacon-mesh-v1\x00"))
}

// Sign signs p with key.
func (p *Packet) Sign(key ed25519.PrivateKey) {
	p.Signature = ed25519.Sign(key, p.signedBytes())
}

// Verify reports whether p carries a valid signature by pub.
func (p *Packet) Verify(pub ed25519.PublicKey) bool {
	return len(p.Signature) == ed25519.SignatureSize && len(pub) == ed25519.PublicKeySize &&
		ed25519.Verify(pub, p.signedBytes(), p.Signature)
}

// header returns the fields a Noise ciphertext binds as associated data: the
// body up to the payload length, with the TTL zeroed.
func (p *Packet) header() []byte {
	q := *p
	q.TTL, q.Payload, q.Signature = 0, nil, nil
	b := q.appendBody(nil)
	return b[:len(b)-2]
}

// ParsePacket decodes and validates one packet. It never allocates more than
// len(data), and the returned packet does not alias data.
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < headerSize+2 || len(data) > MaxPacket {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(data))
	}
	if data[0] != Version {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, data[0])
	}
	p := &Packet{Type: Type(data[1]), TTL: data[2]}
	flags := data[3]
	switch {
	case !p.Type.valid():
		return nil, fmt.Errorf("%w: unknown %v", ErrMalformed, p.Type)
	case p.TTL > MaxTTL:
		return nil, fmt.Errorf("%w: ttl %d", ErrMalformed, p.TTL)
	case flags&^knownFlags != 0:
		return nil, fmt.Errorf("%w: flags %#x", ErrMalformed, flags)
	case p.Type.signed() != (flags&flagSigned != 0):
		return nil, fmt.Errorf("%w: %v signature flag", ErrMalformed, p.Type)
	case p.Type.directed() != (flags&flagRecipient != 0):
		return nil, fmt.Errorf("%w: %v recipient flag", ErrMalformed, p.Type)
	}
	copy(p.ID[:], data[4:])
	ms := binary.BigEndian.Uint64(data[12:])
	if ms > 1<<53 {
		return nil, fmt.Errorf("%w: timestamp", ErrMalformed)
	}
	p.Time = time.UnixMilli(int64(ms))
	copy(p.Sender[:], data[20:])
	rest := data[headerSize:]
	if flags&flagRecipient != 0 {
		if len(rest) < IDSize {
			return nil, fmt.Errorf("%w: truncated", ErrMalformed)
		}
		var r PeerID
		copy(r[:], rest)
		p.Recipient = &r
		rest = rest[IDSize:]
	}
	if len(rest) < 2 {
		return nil, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	sig := 0
	if flags&flagSigned != 0 {
		sig = ed25519.SignatureSize
	}
	if n > MaxPayload || len(rest) != n+sig {
		return nil, fmt.Errorf("%w: payload length %d with %d bytes left", ErrMalformed, n, len(rest))
	}
	p.Payload = append([]byte(nil), rest[:n]...)
	if sig > 0 {
		p.Signature = append([]byte(nil), rest[n:]...)
	}
	return p, nil
}
