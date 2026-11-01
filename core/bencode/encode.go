package bencode

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
)

// Encode encodes v. It accepts the types Decode produces plus int, []byte,
// []string and map[string]string. Dictionary keys are written in sorted order.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case int:
		return encode(buf, int64(v))
	case int64:
		buf.WriteByte('i')
		buf.WriteString(strconv.FormatInt(v, 10))
		buf.WriteByte('e')
	case string:
		buf.WriteString(strconv.Itoa(len(v)))
		buf.WriteByte(':')
		buf.WriteString(v)
	case []byte:
		return encode(buf, string(v))
	case []string:
		buf.WriteByte('l')
		for _, s := range v {
			encode(buf, s)
		}
		buf.WriteByte('e')
	case []any:
		buf.WriteByte('l')
		for _, e := range v {
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	case map[string]string:
		m := make(map[string]any, len(v))
		for k, s := range v {
			m[k] = s
		}
		return encode(buf, m)
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		buf.WriteByte('d')
		for _, k := range keys {
			encode(buf, k)
			if err := encode(buf, v[k]); err != nil {
				return fmt.Errorf("key %q: %w", k, err)
			}
		}
		buf.WriteByte('e')
	default:
		return fmt.Errorf("bencode: cannot encode %T", v)
	}
	return nil
}
