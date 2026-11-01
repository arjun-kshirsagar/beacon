package peer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol is the protocol string sent in every handshake.
const Protocol = "BitTorrent protocol"

// HandshakeLen is the length of an encoded handshake.
const HandshakeLen = 1 + len(Protocol) + 8 + 20 + 20

var (
	// ErrHandshake reports a handshake for a different protocol.
	ErrHandshake = errors.New("peer: bad handshake")
	// ErrTooLarge reports a message longer than the caller's limit.
	ErrTooLarge = errors.New("peer: message too large")
	// ErrMalformed reports a message whose payload does not match its type.
	ErrMalformed = errors.New("peer: malformed message")
)

// Handshake is the first message on every connection.
type Handshake struct {
	Reserved [8]byte
	InfoHash [20]byte
	PeerID   [20]byte
}

// WriteTo writes the encoded handshake to w.
func (h Handshake) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 0, HandshakeLen)
	buf = append(buf, byte(len(Protocol)))
	buf = append(buf, Protocol...)
	buf = append(buf, h.Reserved[:]...)
	buf = append(buf, h.InfoHash[:]...)
	buf = append(buf, h.PeerID[:]...)
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadHandshake reads a handshake from r.
func ReadHandshake(r io.Reader) (Handshake, error) {
	var buf [HandshakeLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Handshake{}, fmt.Errorf("peer: reading handshake: %w", err)
	}
	if int(buf[0]) != len(Protocol) || string(buf[1:1+len(Protocol)]) != Protocol {
		return Handshake{}, ErrHandshake
	}
	var h Handshake
	rest := buf[1+len(Protocol):]
	copy(h.Reserved[:], rest[0:8])
	copy(h.InfoHash[:], rest[8:28])
	copy(h.PeerID[:], rest[28:48])
	return h, nil
}

// MessageID identifies a peer wire message.
type MessageID uint8

const (
	MsgChoke         MessageID = 0
	MsgUnchoke       MessageID = 1
	MsgInterested    MessageID = 2
	MsgNotInterested MessageID = 3
	MsgHave          MessageID = 4
	MsgBitfield      MessageID = 5
	MsgRequest       MessageID = 6
	MsgPiece         MessageID = 7
	MsgCancel        MessageID = 8
)

func (id MessageID) String() string {
	names := [...]string{"choke", "unchoke", "interested", "not-interested", "have", "bitfield", "request", "piece", "cancel"}
	if int(id) < len(names) {
		return names[id]
	}
	return fmt.Sprintf("message(%d)", uint8(id))
}

// Message is a peer wire message. A nil *Message is a keep-alive.
type Message struct {
	ID      MessageID
	Payload []byte
}

// ReadMessage reads one message from r. It returns nil for a keep-alive. max
// bounds the message length (ID plus payload) and is checked before allocating.
func ReadMessage(r io.Reader, max uint32) (*Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, nil
	}
	if n > max {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrTooLarge, n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return &Message{ID: MessageID(buf[0]), Payload: buf[1:]}, nil
}

// WriteMessage writes m to w; a nil m writes a keep-alive.
func WriteMessage(w io.Writer, m *Message) error {
	if m == nil {
		_, err := w.Write([]byte{0, 0, 0, 0})
		return err
	}
	buf := make([]byte, 5+len(m.Payload))
	binary.BigEndian.PutUint32(buf, uint32(1+len(m.Payload)))
	buf[4] = byte(m.ID)
	copy(buf[5:], m.Payload)
	_, err := w.Write(buf)
	return err
}

// Request returns a request (or, with MsgCancel, a cancel) message.
func Request(id MessageID, index, begin, length uint32) *Message {
	p := make([]byte, 12)
	binary.BigEndian.PutUint32(p[0:], index)
	binary.BigEndian.PutUint32(p[4:], begin)
	binary.BigEndian.PutUint32(p[8:], length)
	return &Message{ID: id, Payload: p}
}

// ParseRequest parses a request or cancel message.
func ParseRequest(m *Message) (index, begin, length uint32, err error) {
	if (m.ID != MsgRequest && m.ID != MsgCancel) || len(m.Payload) != 12 {
		return 0, 0, 0, fmt.Errorf("%w: %v with %d-byte payload", ErrMalformed, m.ID, len(m.Payload))
	}
	p := m.Payload
	return binary.BigEndian.Uint32(p[0:]), binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:]), nil
}

// Have returns a have message.
func Have(index uint32) *Message {
	return &Message{ID: MsgHave, Payload: binary.BigEndian.AppendUint32(nil, index)}
}

// ParseHave parses a have message.
func ParseHave(m *Message) (uint32, error) {
	if m.ID != MsgHave || len(m.Payload) != 4 {
		return 0, fmt.Errorf("%w: %v with %d-byte payload", ErrMalformed, m.ID, len(m.Payload))
	}
	return binary.BigEndian.Uint32(m.Payload), nil
}

// Piece returns a piece message carrying block.
func Piece(index, begin uint32, block []byte) *Message {
	p := make([]byte, 8+len(block))
	binary.BigEndian.PutUint32(p[0:], index)
	binary.BigEndian.PutUint32(p[4:], begin)
	copy(p[8:], block)
	return &Message{ID: MsgPiece, Payload: p}
}

// ParsePiece parses a piece message. block aliases m.Payload.
func ParsePiece(m *Message) (index, begin uint32, block []byte, err error) {
	if m.ID != MsgPiece || len(m.Payload) < 8 {
		return 0, 0, nil, fmt.Errorf("%w: %v with %d-byte payload", ErrMalformed, m.ID, len(m.Payload))
	}
	return binary.BigEndian.Uint32(m.Payload[0:]), binary.BigEndian.Uint32(m.Payload[4:]), m.Payload[8:], nil
}
