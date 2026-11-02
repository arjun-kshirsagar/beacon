package bencode

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// MaxDepth is the deepest nesting of lists and dictionaries the decoder accepts.
const MaxDepth = 64

var (
	// ErrSyntax reports malformed bencode.
	ErrSyntax = errors.New("bencode: syntax error")
	// ErrTooDeep reports nesting beyond MaxDepth.
	ErrTooDeep = errors.New("bencode: nesting too deep")
	// ErrTrailing reports data after the top-level value.
	ErrTrailing = errors.New("bencode: trailing data")
	// ErrNotFound reports a missing dictionary key in Raw.
	ErrNotFound = errors.New("bencode: key not found")
)

// Decode decodes exactly one bencoded value from data.
func Decode(data []byte) (any, error) {
	d := decoder{data: data}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, fmt.Errorf("%w at offset %d", ErrTrailing, d.pos)
	}
	return v, nil
}

// DecodePrefix decodes the first bencoded value in data and returns it with the
// number of bytes it occupied, allowing trailing data.
func DecodePrefix(data []byte) (any, int, error) {
	d := decoder{data: data}
	v, err := d.value(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// Raw returns the exact encoded bytes of key's value in the top-level dictionary
// in data. It is used to hash a torrent's info dictionary as it appeared on disk.
func Raw(data []byte, key string) ([]byte, error) {
	d := decoder{data: data}
	if len(data) == 0 || data[0] != 'd' {
		return nil, fmt.Errorf("%w: top-level value is not a dictionary", ErrSyntax)
	}
	d.pos++
	for {
		if d.pos >= len(d.data) {
			return nil, d.errorf("unterminated dictionary")
		}
		if d.data[d.pos] == 'e' {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, key)
		}
		k, err := d.str()
		if err != nil {
			return nil, err
		}
		start := d.pos
		if _, err := d.value(1); err != nil {
			return nil, err
		}
		if k == key {
			return data[start:d.pos], nil
		}
	}
}

type decoder struct {
	data []byte
	pos  int
}

func (d *decoder) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s at offset %d", ErrSyntax, fmt.Sprintf(format, args...), d.pos)
}

func (d *decoder) value(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	if d.pos >= len(d.data) {
		return nil, d.errorf("unexpected end of input")
	}
	switch c := d.data[d.pos]; {
	case c == 'i':
		return d.integer()
	case c == 'l':
		d.pos++
		list := []any{}
		for {
			if d.pos >= len(d.data) {
				return nil, d.errorf("unterminated list")
			}
			if d.data[d.pos] == 'e' {
				d.pos++
				return list, nil
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
	case c == 'd':
		d.pos++
		dict := map[string]any{}
		for {
			if d.pos >= len(d.data) {
				return nil, d.errorf("unterminated dictionary")
			}
			if d.data[d.pos] == 'e' {
				d.pos++
				return dict, nil
			}
			k, err := d.str()
			if err != nil {
				return nil, err
			}
			if _, dup := dict[k]; dup {
				return nil, d.errorf("duplicate key %q", k)
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			dict[k] = v
		}
	case c >= '0' && c <= '9':
		return d.str()
	default:
		return nil, d.errorf("unexpected byte %q", c)
	}
}

func (d *decoder) integer() (int64, error) {
	d.pos++ // 'i'
	end := bytes.IndexByte(d.data[d.pos:], 'e')
	if end < 0 {
		return 0, d.errorf("unterminated integer")
	}
	n, err := parseInt(d.data[d.pos : d.pos+end])
	if err != nil {
		return 0, d.errorf("%v", err)
	}
	d.pos += end + 1
	return n, nil
}

func (d *decoder) str() (string, error) {
	if d.pos >= len(d.data) || d.data[d.pos] < '0' || d.data[d.pos] > '9' {
		return "", d.errorf("expected string")
	}
	colon := bytes.IndexByte(d.data[d.pos:], ':')
	if colon < 0 {
		return "", d.errorf("missing ':' after string length")
	}
	n, err := parseInt(d.data[d.pos : d.pos+colon])
	if err != nil || n < 0 {
		return "", d.errorf("bad string length")
	}
	start := d.pos + colon + 1
	// Check the length against the remaining input before slicing or allocating.
	if n > int64(len(d.data)-start) {
		return "", d.errorf("string length %d exceeds input", n)
	}
	d.pos = start + int(n)
	return string(d.data[start:d.pos]), nil
}

// parseInt parses a decimal integer with bencode's rules: optional '-', digits
// only, no leading zeros, and no negative zero.
func parseInt(b []byte) (int64, error) {
	digits := b
	neg := len(b) > 0 && b[0] == '-'
	if neg {
		digits = b[1:]
	}
	if len(digits) == 0 {
		return 0, errors.New("empty integer")
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid integer %q", b)
		}
	}
	if digits[0] == '0' && (len(digits) > 1 || neg) {
		return 0, fmt.Errorf("non-canonical integer %q", b)
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("integer out of range %q", b)
	}
	return n, nil
}
