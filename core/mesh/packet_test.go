package mesh

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"
)

func samplePacket(typ Type) *Packet {
	p := &Packet{Type: typ, TTL: MaxTTL, ID: PacketID{1, 2, 3, 4, 5, 6, 7, 8},
		Time: time.UnixMilli(1_762_000_000_000), Sender: PeerID{9, 9, 9, 9, 9, 9, 9, 9}, Payload: []byte("hello")}
	if typ.directed() {
		p.Recipient = &PeerID{7, 7, 7, 7, 7, 7, 7, 7}
	}
	return p
}

func TestPacketRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for _, typ := range []Type{TypeAnnounce, TypeChannel, TypeHandshake, TypeEncrypted} {
		p := samplePacket(typ)
		if typ.signed() {
			p.Sign(priv)
		}
		q, err := ParsePacket(p.Encode())
		if err != nil {
			t.Fatalf("%v: %v", typ, err)
		}
		if !bytes.Equal(q.Encode(), p.Encode()) || !q.Time.Equal(p.Time) {
			t.Fatalf("%v: round trip changed the packet", typ)
		}
		if typ.signed() && !q.Verify(pub) {
			t.Fatalf("%v: signature does not verify", typ)
		}
	}
}

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	p := samplePacket(TypeChannel)
	p.Sign(priv)
	enc := p.Encode()

	// Relays lower the TTL; the signature still holds.
	relayed, _ := ParsePacket(enc)
	relayed.TTL = 2
	if !relayed.Verify(pub) {
		t.Fatal("TTL change broke the signature")
	}
	if p.Verify(other) {
		t.Fatal("verified with the wrong key")
	}
	// Any other change breaks it.
	for i := range len(enc) - ed25519.SignatureSize {
		if i == 2 { // TTL
			continue
		}
		mod := append([]byte(nil), enc...)
		mod[i] ^= 0x01
		q, err := ParsePacket(mod)
		if err == nil && q.Verify(pub) {
			t.Fatalf("byte %d changed and the signature still verified", i)
		}
	}
}

func TestParseRejects(t *testing.T) {
	good := samplePacket(TypeHandshake).Encode()
	set := func(i int, v byte) []byte {
		b := append([]byte(nil), good...)
		b[i] = v
		return b
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", good[:10]},
		{"version", set(0, 2)},
		{"unknown type", set(1, 0x7f)},
		{"ttl over max", set(2, MaxTTL+1)},
		{"unknown flag", set(3, 0x81)},
		{"directed without recipient", set(3, 0)},
		{"unsigned announce", set(1, byte(TypeAnnounce))},
		{"truncated payload", good[:len(good)-1]},
		{"trailing bytes", append(append([]byte(nil), good...), 0)},
		{"too large", make([]byte, MaxPacket+1)},
	}
	for _, tt := range tests {
		if _, err := ParsePacket(tt.data); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err %v", tt.name, err)
		}
	}
	big := samplePacket(TypeChannel)
	big.Payload = make([]byte, MaxPayload+1)
	big.Signature = make([]byte, 64)
	if _, err := ParsePacket(big.Encode()); err == nil {
		t.Error("payload over MaxPayload accepted")
	}
}

func TestFragment(t *testing.T) {
	for _, mtu := range []int{MinMTU, 23, 185, 512} {
		for _, size := range []int{0, 1, mtu - 1, mtu, 3 * mtu, MaxPacket} {
			pkt := bytes.Repeat([]byte{0xab}, size)
			for i := range pkt {
				pkt[i] = byte(i)
			}
			var a assembler
			var got []byte
			frames := fragment(pkt, mtu)
			for i, f := range frames {
				if len(f) > mtu {
					t.Fatalf("mtu %d: frame of %d bytes", mtu, len(f))
				}
				out, err := a.add(f)
				if err != nil {
					t.Fatal(err)
				}
				if out != nil && i != len(frames)-1 {
					t.Fatal("packet completed early")
				}
				got = out
			}
			if !bytes.Equal(got, pkt) {
				t.Fatalf("mtu %d size %d: reassembled %d bytes", mtu, size, len(got))
			}
		}
	}
}

func TestAssemblerRecovers(t *testing.T) {
	pkt := bytes.Repeat([]byte("x"), 100)
	frames := fragment(pkt, 30)
	var a assembler
	// The end of the first packet is lost; the next packet still arrives.
	for _, f := range frames[:2] {
		a.add(f)
	}
	var got []byte
	for _, f := range frames {
		out, err := a.add(f)
		if err != nil {
			t.Fatal(err)
		}
		got = out
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("did not resynchronise on a start frame")
	}
	// A continuation with no start is refused.
	if _, err := a.add(frames[1]); err == nil {
		t.Fatal("orphan continuation accepted")
	}
	// The assembler never grows past MaxPacket.
	a.add([]byte{frameStart})
	chunk := append([]byte{0}, make([]byte, 1000)...)
	var err error
	for range MaxPacket/1000 + 2 {
		if _, err = a.add(chunk); err != nil {
			break
		}
	}
	if err == nil || len(a.buf) > MaxPacket {
		t.Fatal("assembler grew past MaxPacket")
	}
}

func TestSeen(t *testing.T) {
	s := newSeen(1000, 1e-6)
	for i := range 1000 {
		if s.check(fmt.Appendf(nil, "p%d", i)) {
			t.Fatalf("fresh key %d reported seen", i)
		}
	}
	for i := range 1000 {
		if !s.check(fmt.Appendf(nil, "p%d", i)) {
			t.Fatalf("key %d forgotten", i)
		}
	}
	// After two more generations the first keys age out.
	for i := range 2000 {
		s.check(fmt.Appendf(nil, "q%d", i))
	}
	forgotten := 0
	for i := range 1000 {
		if !s.check(fmt.Appendf(nil, "p%d", i)) {
			forgotten++
		}
	}
	if forgotten < 990 {
		t.Fatalf("only %d of 1000 old keys aged out", forgotten)
	}
}

func FuzzParsePacket(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(nil)
	for _, typ := range []Type{TypeAnnounce, TypeChannel, TypeHandshake, TypeEncrypted} {
		p := samplePacket(typ)
		if typ.signed() {
			p.Sign(priv)
		}
		f.Add(p.Encode())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePacket(data)
		if err != nil {
			return
		}
		if !bytes.Equal(p.Encode(), data) {
			t.Fatalf("re-encoding changed the packet:\n%x\n%x", data, p.Encode())
		}
	})
}

func FuzzAssembler(f *testing.F) {
	f.Add([]byte{3, 1, 2, 3}, uint8(30))
	f.Add([]byte{1, 1, 2, 0, 3, 2, 4}, uint8(4))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		// Split data into frames of size bytes and feed them in.
		n := int(size)%64 + 1
		var a assembler
		for i := 0; i < len(data); i += n {
			out, _ := a.add(data[i:min(i+n, len(data))])
			if len(out) > MaxPacket || len(a.buf) > MaxPacket {
				t.Fatal("assembler exceeded MaxPacket")
			}
		}
	})
}
