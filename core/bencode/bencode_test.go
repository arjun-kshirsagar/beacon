package bencode

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		in   string
		want any
	}{
		{"i0e", int64(0)},
		{"i42e", int64(42)},
		{"i-42e", int64(-42)},
		{"i9223372036854775807e", int64(9223372036854775807)},
		{"0:", ""},
		{"4:spam", "spam"},
		{"le", []any{}},
		{"l4:spami42ee", []any{"spam", int64(42)}},
		{"de", map[string]any{}},
		{"d3:bar4:spam3:fooi42ee", map[string]any{"bar": "spam", "foo": int64(42)}},
		{"d1:ld1:xleee", map[string]any{"l": map[string]any{"x": []any{}}}},
	}
	for _, tt := range tests {
		got, err := Decode([]byte(tt.in))
		if err != nil {
			t.Errorf("Decode(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Decode(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		in   string
		want error
	}{
		{"", ErrSyntax},
		{"i", ErrSyntax},
		{"ie", ErrSyntax},
		{"i-e", ErrSyntax},
		{"i-0e", ErrSyntax},
		{"i03e", ErrSyntax},
		{"i+3e", ErrSyntax},
		{"i1.5e", ErrSyntax},
		{"i9223372036854775808e", ErrSyntax},
		{"5:abc", ErrSyntax},
		{"-1:a", ErrSyntax},
		{"01:a", ErrSyntax},
		{"99999999999999999999:a", ErrSyntax},
		{"4spam", ErrSyntax},
		{"l", ErrSyntax},
		{"l4:spam", ErrSyntax},
		{"d", ErrSyntax},
		{"di1ei2ee", ErrSyntax},
		{"d1:a", ErrSyntax},
		{"d1:ai1e1:ai2ee", ErrSyntax},
		{"x", ErrSyntax},
		{"i1ei2e", ErrTrailing},
		{strings.Repeat("l", MaxDepth+2) + strings.Repeat("e", MaxDepth+2), ErrTooDeep},
	}
	for _, tt := range tests {
		if _, err := Decode([]byte(tt.in)); !errors.Is(err, tt.want) {
			t.Errorf("Decode(%q): got %v, want %v", tt.in, err, tt.want)
		}
	}
}

func TestEncode(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{42, "i42e"},
		{int64(-7), "i-7e"},
		{"spam", "4:spam"},
		{[]byte{0, 1}, "2:\x00\x01"},
		{[]string{"a", "bc"}, "l1:a2:bce"},
		{[]any{"a", 1}, "l1:ai1ee"},
		{map[string]any{"z": 1, "a": "x"}, "d1:a1:x1:zi1ee"},
		{map[string]string{"k": "v"}, "d1:k1:ve"},
	}
	for _, tt := range tests {
		got, err := Encode(tt.in)
		if err != nil {
			t.Errorf("Encode(%#v): %v", tt.in, err)
			continue
		}
		if string(got) != tt.want {
			t.Errorf("Encode(%#v) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if _, err := Encode(3.14); err == nil {
		t.Error("Encode(float) succeeded")
	}
}

func TestRaw(t *testing.T) {
	// Keys out of order: Raw must return the original bytes, not a re-encoding.
	data := []byte("d8:announce3:url4:infod6:lengthi5e4:name1:xe1:zi1ee")
	got, err := Raw(data, "info")
	if err != nil {
		t.Fatal(err)
	}
	if want := "d6:lengthi5e4:name1:xe"; string(got) != want {
		t.Fatalf("Raw = %q, want %q", got, want)
	}
	if _, err := Raw(data, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: got %v", err)
	}
	if _, err := Raw([]byte("le"), "info"); !errors.Is(err, ErrSyntax) {
		t.Fatalf("non-dict: got %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"i42e", "4:spam", "l4:spami42ee", "d3:bar4:spam3:fooi42ee", "d1:ld1:xleee"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return
		}
		enc, err := Encode(v)
		if err != nil {
			t.Fatalf("Encode of decoded value failed: %v", err)
		}
		v2, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("round trip mismatch: %#v != %#v", v, v2)
		}
		Raw(data, "info")
	})
}
