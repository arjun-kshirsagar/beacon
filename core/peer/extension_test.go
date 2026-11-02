package peer

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestExtensionBit(t *testing.T) {
	var h Handshake
	if h.SupportsExtensions() {
		t.Fatal("zero handshake supports extensions")
	}
	h.SetExtensions()
	if !h.SupportsExtensions() || h.Reserved[5] != 0x10 {
		t.Fatalf("reserved %x", h.Reserved)
	}
}

func TestExtHandshake(t *testing.T) {
	e := ExtHandshake{M: map[string]int{ExtMetadata: 3}, MetadataSize: 40000, Version: "Beacon", Port: 6881}
	id, body, err := ParseExtended(Extended(ExtHandshakeID, e.Encode()))
	if err != nil || id != ExtHandshakeID {
		t.Fatalf("ParseExtended: %d %v", id, err)
	}
	got, err := ParseExtHandshake(body)
	if err != nil || !reflect.DeepEqual(got, e) {
		t.Fatalf("got %+v, %v", got, err)
	}

	// Out-of-range values are dropped, not trusted.
	got, err = ParseExtHandshake([]byte("d1:md1:ai0e1:bi300e1:ci-1e1:di7ee13:metadata_sizei99999999999e1:pi70000ee"))
	if err != nil || !reflect.DeepEqual(got.M, map[string]int{"d": 7}) || got.MetadataSize != 0 || got.Port != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := ParseExtHandshake([]byte("le")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("list: %v", err)
	}
	if _, _, err := ParseExtended(&Message{ID: MsgExtended}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty extended: %v", err)
	}
}

func TestMetadataMsg(t *testing.T) {
	msgs := []MetadataMsg{
		{Type: MetadataRequest, Piece: 2},
		{Type: MetadataReject, Piece: 0},
		{Type: MetadataData, Piece: 1, TotalSize: 20000, Data: bytes.Repeat([]byte("x"), 3616)},
	}
	for _, m := range msgs {
		got, err := ParseMetadataMsg(m.Encode())
		if err != nil || !reflect.DeepEqual(got, m) {
			t.Errorf("round trip %+v: got %+v, %v", m, got, err)
		}
	}
	bad := [][]byte{
		[]byte("d8:msg_typei9e5:piecei0ee"),
		[]byte("d8:msg_typei0e5:piecei-1ee"),
		[]byte("d8:msg_typei0e5:piecei0eeextra"),
		[]byte("d8:msg_typei1e5:piecei0e10:total_sizei0ee"),
		append([]byte("d8:msg_typei1e5:piecei0e10:total_sizei5ee"), make([]byte, MetadataPieceSize+1)...),
	}
	for _, b := range bad {
		if _, err := ParseMetadataMsg(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%.40q: got %v", b, err)
		}
	}
}

func FuzzExtension(f *testing.F) {
	f.Add([]byte("d1:md11:ut_metadatai1ee13:metadata_sizei1000ee"))
	f.Add([]byte("d8:msg_typei1e5:piecei0e10:total_sizei3eeabc"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if e, err := ParseExtHandshake(body); err == nil {
			if len(e.M) > maxExtensions || e.MetadataSize < 0 || e.MetadataSize > MaxMetadataSize {
				t.Fatalf("unbounded handshake %+v", e)
			}
		}
		if m, err := ParseMetadataMsg(body); err == nil && len(m.Data) > MetadataPieceSize {
			t.Fatalf("oversized metadata piece %d", len(m.Data))
		}
	})
}
