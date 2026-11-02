package dht

import (
	"errors"
	"fmt"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

// ErrMalformed reports a KRPC message that does not follow BEP 5.
var ErrMalformed = errors.New("dht: malformed message")

const maxTIDLen = 16

// message is a decoded KRPC message.
type message struct {
	T    string         // transaction ID
	Y    string         // "q", "r" or "e"
	Q    string         // query method
	A    map[string]any // query arguments
	R    map[string]any // response values
	Code int64          // error code
	Msg  string         // error message
}

// parseMessage decodes and validates the envelope of a KRPC message.
func parseMessage(b []byte) (*message, error) {
	v, err := bencode.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not a dictionary", ErrMalformed)
	}
	m := &message{}
	m.T, _ = d["t"].(string)
	m.Y, _ = d["y"].(string)
	if m.T == "" || len(m.T) > maxTIDLen {
		return nil, fmt.Errorf("%w: bad transaction ID", ErrMalformed)
	}
	switch m.Y {
	case "q":
		m.Q, _ = d["q"].(string)
		m.A, _ = d["a"].(map[string]any)
		if m.Q == "" || m.A == nil {
			return nil, fmt.Errorf("%w: query without method or arguments", ErrMalformed)
		}
	case "r":
		m.R, _ = d["r"].(map[string]any)
		if m.R == nil {
			return nil, fmt.Errorf("%w: response without values", ErrMalformed)
		}
	case "e":
		e, _ := d["e"].([]any)
		if len(e) >= 1 {
			m.Code, _ = e[0].(int64)
		}
		if len(e) >= 2 {
			m.Msg, _ = e[1].(string)
		}
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrMalformed, m.Y)
	}
	return m, nil
}

// id20 returns the 20-byte string at key in d.
func id20(d map[string]any, key string) (ID, bool) {
	s, ok := d[key].(string)
	if !ok || len(s) != 20 {
		return ID{}, false
	}
	return ID([]byte(s)), true
}

func encodeQuery(tid, method string, args map[string]any) []byte {
	b, _ := bencode.Encode(map[string]any{"t": tid, "y": "q", "q": method, "a": args})
	return b
}

func encodeResponse(tid string, values map[string]any) []byte {
	b, _ := bencode.Encode(map[string]any{"t": tid, "y": "r", "r": values})
	return b
}

func encodeError(tid string, code int, msg string) []byte {
	b, _ := bencode.Encode(map[string]any{"t": tid, "y": "e", "e": []any{code, msg}})
	return b
}

// KRPC error codes.
const (
	errGeneric  = 201
	errProtocol = 203
	errMethod   = 204
)
