package peer

import (
	"fmt"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

// MsgExtended carries extension protocol messages (BEP 10).
const MsgExtended MessageID = 20

const (
	// ExtHandshakeID is the extended message ID of the extension handshake.
	ExtHandshakeID = 0
	// ExtMetadata is the extension name for metadata exchange (BEP 9).
	ExtMetadata = "ut_metadata"
	// MetadataPieceSize is the size of every metadata piece but the last.
	MetadataPieceSize = 16 << 10
	// MaxMetadataSize bounds the info dictionary size we accept from peers.
	MaxMetadataSize = 16 << 20

	maxExtensions = 64
)

// SetExtensions advertises extension protocol support in the reserved bytes.
func (h *Handshake) SetExtensions() { h.Reserved[5] |= 0x10 }

// SupportsExtensions reports whether the handshake advertises BEP 10.
func (h Handshake) SupportsExtensions() bool { return h.Reserved[5]&0x10 != 0 }

// Extended returns an extended message with the given extended ID and body.
func Extended(id uint8, body []byte) *Message {
	return &Message{ID: MsgExtended, Payload: append([]byte{id}, body...)}
}

// ParseExtended splits an extended message into its extended ID and body.
func ParseExtended(m *Message) (uint8, []byte, error) {
	if m.ID != MsgExtended || len(m.Payload) < 1 {
		return 0, nil, fmt.Errorf("%w: %v with %d-byte payload", ErrMalformed, m.ID, len(m.Payload))
	}
	return m.Payload[0], m.Payload[1:], nil
}

// ExtHandshake is the extension handshake dictionary.
type ExtHandshake struct {
	M            map[string]int // extension name → the sender's message ID; 0 disables
	MetadataSize int            // size of the info dictionary, if known
	Version      string
	Port         int // the sender's listening port, if any
}

// Encode returns the bencoded handshake body.
func (e ExtHandshake) Encode() []byte {
	m := map[string]any{}
	for k, v := range e.M {
		m[k] = v
	}
	d := map[string]any{"m": m}
	if e.MetadataSize > 0 {
		d["metadata_size"] = e.MetadataSize
	}
	if e.Version != "" {
		d["v"] = e.Version
	}
	if e.Port > 0 {
		d["p"] = e.Port
	}
	b, _ := bencode.Encode(d) // only encodable types above
	return b
}

// ParseExtHandshake parses an extension handshake body, dropping entries that are
// out of range rather than rejecting the whole handshake.
func ParseExtHandshake(body []byte) (ExtHandshake, error) {
	v, err := bencode.Decode(body)
	if err != nil {
		return ExtHandshake{}, fmt.Errorf("%w: extension handshake: %w", ErrMalformed, err)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return ExtHandshake{}, fmt.Errorf("%w: extension handshake is not a dictionary", ErrMalformed)
	}
	e := ExtHandshake{M: map[string]int{}}
	if m, ok := d["m"].(map[string]any); ok {
		for name, id := range m {
			if n, ok := id.(int64); ok && n > 0 && n < 256 && len(e.M) < maxExtensions {
				e.M[name] = int(n)
			}
		}
	}
	if n, ok := d["metadata_size"].(int64); ok && n > 0 && n <= MaxMetadataSize {
		e.MetadataSize = int(n)
	}
	if s, ok := d["v"].(string); ok && len(s) <= 64 {
		e.Version = s
	}
	if p, ok := d["p"].(int64); ok && p > 0 && p < 65536 {
		e.Port = int(p)
	}
	return e, nil
}

// Metadata message types (BEP 9).
const (
	MetadataRequest = 0
	MetadataData    = 1
	MetadataReject  = 2
)

// MetadataMsg is a ut_metadata message.
type MetadataMsg struct {
	Type      int
	Piece     int
	TotalSize int    // data messages only
	Data      []byte // data messages only
}

// Encode returns the message body: a bencoded dictionary followed, for data
// messages, by the piece bytes.
func (m MetadataMsg) Encode() []byte {
	d := map[string]any{"msg_type": m.Type, "piece": m.Piece}
	if m.Type == MetadataData {
		d["total_size"] = m.TotalSize
	}
	b, _ := bencode.Encode(d)
	return append(b, m.Data...)
}

// ParseMetadataMsg parses a ut_metadata message body.
func ParseMetadataMsg(body []byte) (MetadataMsg, error) {
	v, n, err := bencode.DecodePrefix(body)
	if err != nil {
		return MetadataMsg{}, fmt.Errorf("%w: metadata message: %w", ErrMalformed, err)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return MetadataMsg{}, fmt.Errorf("%w: metadata message is not a dictionary", ErrMalformed)
	}
	typ, ok1 := d["msg_type"].(int64)
	piece, ok2 := d["piece"].(int64)
	if !ok1 || !ok2 || typ < MetadataRequest || typ > MetadataReject || piece < 0 || piece >= MaxMetadataSize/MetadataPieceSize {
		return MetadataMsg{}, fmt.Errorf("%w: bad metadata message fields", ErrMalformed)
	}
	m := MetadataMsg{Type: int(typ), Piece: int(piece)}
	rest := body[n:]
	if m.Type != MetadataData {
		if len(rest) != 0 {
			return MetadataMsg{}, fmt.Errorf("%w: trailing data on metadata message", ErrMalformed)
		}
		return m, nil
	}
	total, ok := d["total_size"].(int64)
	if !ok || total <= 0 || total > MaxMetadataSize || len(rest) > MetadataPieceSize {
		return MetadataMsg{}, fmt.Errorf("%w: bad metadata data message", ErrMalformed)
	}
	m.TotalSize = int(total)
	m.Data = rest
	return m, nil
}
