package peer

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestHandshakeRoundTrip(t *testing.T) {
	h := Handshake{}
	copy(h.InfoHash[:], "info-hash-0123456789")
	copy(h.PeerID[:], "-BC0001-abcdefghijkl")
	h.Reserved[5] = 0x10
	var buf bytes.Buffer
	if _, err := h.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != HandshakeLen {
		t.Fatalf("handshake is %d bytes", buf.Len())
	}
	got, err := ReadHandshake(&buf)
	if err != nil || got != h {
		t.Fatalf("got %+v, %v", got, err)
	}

	bad := bytes.Repeat([]byte{19}, HandshakeLen)
	if _, err := ReadHandshake(bytes.NewReader(bad)); !errors.Is(err, ErrHandshake) {
		t.Fatalf("bad protocol: got %v", err)
	}
	if _, err := ReadHandshake(bytes.NewReader(bad[:10])); err == nil {
		t.Fatal("short handshake accepted")
	}
}

func TestMessages(t *testing.T) {
	msgs := []*Message{
		nil,
		{ID: MsgInterested},
		Have(7),
		Request(MsgRequest, 1, 16384, 16384),
		Piece(2, 0, []byte("block")),
		{ID: MsgBitfield, Payload: []byte{0xa0}},
	}
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := WriteMessage(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range msgs {
		got, err := ReadMessage(&buf, 1<<10)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if want != nil && len(want.Payload) == 0 {
			want = &Message{ID: want.ID, Payload: []byte{}}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("message %d: got %+v, want %+v", i, got, want)
		}
	}
	if _, err := ReadMessage(&buf, 1<<10); err != io.EOF {
		t.Fatalf("end: got %v", err)
	}
}

func TestReadMessageLimit(t *testing.T) {
	// A 4 GiB length prefix must be rejected without allocating.
	_, err := ReadMessage(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 7}), 1<<14)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{0, 0, 0, 5, 7, 1}), 1<<14); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: got %v", err)
	}
}

func TestParsers(t *testing.T) {
	i, b, l, err := ParseRequest(Request(MsgCancel, 1, 2, 3))
	if err != nil || i != 1 || b != 2 || l != 3 {
		t.Errorf("ParseRequest = %d %d %d %v", i, b, l, err)
	}
	if _, _, _, err := ParseRequest(&Message{ID: MsgRequest, Payload: make([]byte, 11)}); !errors.Is(err, ErrMalformed) {
		t.Errorf("short request: %v", err)
	}
	if _, _, _, err := ParseRequest(Have(1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("wrong id: %v", err)
	}
	if h, err := ParseHave(Have(9)); err != nil || h != 9 {
		t.Errorf("ParseHave = %d %v", h, err)
	}
	if _, err := ParseHave(&Message{ID: MsgHave}); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty have: %v", err)
	}
	idx, begin, block, err := ParsePiece(Piece(3, 4, []byte("xy")))
	if err != nil || idx != 3 || begin != 4 || string(block) != "xy" {
		t.Errorf("ParsePiece = %d %d %q %v", idx, begin, block, err)
	}
	if _, _, _, err := ParsePiece(&Message{ID: MsgPiece, Payload: make([]byte, 7)}); !errors.Is(err, ErrMalformed) {
		t.Errorf("short piece: %v", err)
	}
}

func TestBitfield(t *testing.T) {
	b := NewBitfield(10)
	if len(b) != 2 {
		t.Fatalf("len %d", len(b))
	}
	b.Set(0)
	b.Set(9)
	b.Set(100) // ignored
	if !b.Has(0) || !b.Has(9) || b.Has(1) || b.Has(-1) || b.Has(100) || b.Count() != 2 {
		t.Fatalf("bitfield %08b", b)
	}
	if _, err := ParseBitfield([]byte{0xff, 0xc0}, 10); err != nil {
		t.Errorf("valid bitfield: %v", err)
	}
	if _, err := ParseBitfield([]byte{0xff, 0xe0}, 10); !errors.Is(err, ErrMalformed) {
		t.Errorf("spare bits: %v", err)
	}
	if _, err := ParseBitfield([]byte{0xff}, 10); !errors.Is(err, ErrMalformed) {
		t.Errorf("short: %v", err)
	}
}

func FuzzReadMessage(f *testing.F) {
	for _, m := range []*Message{Have(1), Request(MsgRequest, 0, 0, 16384), Piece(0, 0, []byte("abc")), {ID: MsgBitfield, Payload: []byte{0xf0}}} {
		var buf bytes.Buffer
		WriteMessage(&buf, m)
		f.Add(buf.Bytes())
	}
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		for {
			m, err := ReadMessage(r, 1<<15)
			if err != nil {
				return
			}
			if m == nil {
				continue
			}
			switch m.ID {
			case MsgHave:
				ParseHave(m)
			case MsgRequest, MsgCancel:
				ParseRequest(m)
			case MsgPiece:
				ParsePiece(m)
			case MsgBitfield:
				if bf, err := ParseBitfield(m.Payload, len(m.Payload)*8-3); err == nil {
					bf.Count()
				}
			}
		}
	})
}
