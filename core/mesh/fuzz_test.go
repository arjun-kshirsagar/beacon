package mesh

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/noise"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func FuzzPayloads(f *testing.F) {
	id, _ := NewIdentity()
	f.Add(uint8(0), announce{signKey: id.SigningKey(), noiseKey: id.NoiseKey(), nickname: "alice"}.encode())
	f.Add(uint8(1), channelMessage{channel: "#general", text: "hi"}.encode())
	f.Add(uint8(2), padText("hello"))
	f.Add(uint8(3), id.identityProof())
	f.Add(uint8(4), sharePayload([20]byte{1}, "file.bin", 1234))
	f.Add(uint8(5), padInner(innerData, []byte{1, 2}))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		switch kind % 6 {
		case 0:
			if a, err := parseAnnounce(data); err == nil && string(a.encode()) != string(data) {
				t.Fatal("announce did not round-trip")
			}
		case 1:
			if m, err := parseChannelMessage(data); err == nil && string(m.encode()) != string(data) {
				t.Fatal("channel message did not round-trip")
			}
		case 2:
			if text, err := unpadText(data); err == nil && len(text) > MaxText {
				t.Fatal("oversized text accepted")
			}
		case 3:
			checkProof(data, id.NoiseKey())
		case 4:
			if ih, name, size, err := parseShare(data); err == nil && string(sharePayload(ih, name, size)) != string(data) {
				t.Fatal("share did not round-trip")
			}
		case 5:
			if kind, body, err := unpadInner(data); err == nil && (len(body) > MaxData || kind != innerText && kind != innerData) {
				t.Fatal("bad inner message accepted")
			}
		}
	})
}

var fuzzEpoch = time.UnixMilli(1_767_225_600_000)

// fuzzNode is a node with a fixed ID and clock and no running goroutines,
// so packets can be pushed straight into it.
func fuzzNode(t testing.TB) (*Node, *link) {
	id, _ := UnmarshalIdentity(make([]byte, IdentitySize))
	n, err := New(Config{Identity: id, Nickname: "fuzz", Links: transport.NewRadio(185).Node("x"),
		Now: func() time.Time { return fuzzEpoch }})
	if err != nil {
		t.Fatal(err)
	}
	n.myID, n.prevID = PeerID{1, 1, 1, 1, 1, 1, 1, 1}, PeerID{1, 1, 1, 1, 1, 1, 1, 1}
	l := &link{out: make(chan []byte, 1<<16), done: make(chan struct{})}
	n.links[l] = true
	return n, l
}

// framed joins packets as the fuzz input: each with a 2-byte length.
func framed(packets ...[]byte) []byte {
	var b []byte
	for _, p := range packets {
		b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
		b = append(b, p...)
	}
	return b
}

// FuzzNode feeds a sequence of arbitrary packets to a node and checks that
// it stays within its bounds.
func FuzzNode(f *testing.F) {
	peer, _ := NewIdentity()
	me := PeerID{1, 1, 1, 1, 1, 1, 1, 1}
	stamp := func(p *Packet) *Packet {
		p.TTL, p.Time, p.Sender = 3, fuzzEpoch, PeerID{2, 2, 2, 2, 2, 2, 2, 2}
		p.ID = PacketID(randomID())
		return p
	}
	ann := stamp(&Packet{Type: TypeAnnounce,
		Payload: announce{signKey: peer.SigningKey(), noiseKey: peer.NoiseKey(), nickname: "p"}.encode()})
	ann.Sign(peer.sign)
	ch := stamp(&Packet{Type: TypeChannel, Payload: channelMessage{channel: "#general", text: "x"}.encode()})
	ch.Sign(peer.sign)
	hs := noise.NewHandshake(noise.Config{Initiator: true, Static: peer.noise, Prologue: noisePrologue})
	m1, _ := hs.WriteMessage([]byte{hsStep1}, nil)
	step1 := stamp(&Packet{Type: TypeHandshake, Recipient: &me, Payload: m1})
	enc := stamp(&Packet{Type: TypeEncrypted, Recipient: &me, Payload: make([]byte, 8+16+64)})
	f.Add(framed(ann.Encode(), ch.Encode()))
	f.Add(framed(ch.Encode(), ann.Encode()))
	f.Add(framed(ann.Encode(), step1.Encode(), enc.Encode()))

	f.Fuzz(func(t *testing.T, data []byte) {
		n, l := fuzzNode(t)
		for len(data) >= 2 {
			size := int(binary.BigEndian.Uint16(data))
			data = data[2:]
			if size > len(data) {
				size = len(data)
			}
			n.receive(l, data[:size])
			data = data[size:]
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		n.expireLocked(fuzzEpoch)
		n.dm.tick(n, fuzzEpoch)
		if len(n.peers) > maxPeers || len(n.pending) > maxPendingFrom || len(n.store) > maxStored ||
			len(n.dm.responders) > maxHandshakes || len(n.dm.sessions) > maxSessions {
			t.Fatalf("state over its bounds: %d peers, %d pending, %d stored, %d responders",
				len(n.peers), len(n.pending), len(n.store), len(n.dm.responders))
		}
		for _, q := range n.pending {
			if len(q) > maxPending {
				t.Fatal("pending queue over its bound")
			}
		}
	})
}
