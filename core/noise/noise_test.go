package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type vector struct {
	ProtocolName  string `json:"protocol_name"`
	InitPrologue  string `json:"init_prologue"`
	InitStatic    string `json:"init_static"`
	InitEphemeral string `json:"init_ephemeral"`
	RespPrologue  string `json:"resp_prologue"`
	RespStatic    string `json:"resp_static"`
	RespEphemeral string `json:"resp_ephemeral"`
	HandshakeHash string `json:"handshake_hash"`
	Messages      []struct {
		Payload    string `json:"payload"`
		Ciphertext string `json:"ciphertext"`
	} `json:"messages"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func key(t *testing.T, s string) Key {
	t.Helper()
	k, err := KeyFromPrivate(unhex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestVectors replays the cacophony vectors for this protocol: every handshake
// and transport message must match byte for byte in both directions.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/cacophony_xx.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Vectors []vector }
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		if v.ProtocolName != ProtocolName {
			t.Fatalf("vector for %s", v.ProtocolName)
		}
		init := NewHandshake(Config{Initiator: true, Static: key(t, v.InitStatic), Prologue: unhex(t, v.InitPrologue),
			random: bytes.NewReader(unhex(t, v.InitEphemeral))})
		resp := NewHandshake(Config{Static: key(t, v.RespStatic), Prologue: unhex(t, v.RespPrologue),
			random: bytes.NewReader(unhex(t, v.RespEphemeral))})

		var iSend, iRecv, rSend, rRecv *CipherState
		for i, m := range v.Messages {
			payload, want := unhex(t, m.Payload), unhex(t, m.Ciphertext)
			fromInit := i%2 == 0
			var ct, pt []byte
			var err error
			switch {
			case i < 3 && fromInit:
				ct, err = init.WriteMessage(nil, payload)
				if err == nil {
					pt, err = resp.ReadMessage(nil, ct)
				}
			case i < 3:
				ct, err = resp.WriteMessage(nil, payload)
				if err == nil {
					pt, err = init.ReadMessage(nil, ct)
				}
			case fromInit:
				ct, err = iSend.Encrypt(nil, nil, payload)
				if err == nil {
					pt, err = rRecv.Decrypt(nil, nil, ct)
				}
			default:
				ct, err = rSend.Encrypt(nil, nil, payload)
				if err == nil {
					pt, err = iRecv.Decrypt(nil, nil, ct)
				}
			}
			if err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
			if !bytes.Equal(ct, want) {
				t.Fatalf("message %d ciphertext\n got %x\nwant %x", i, ct, want)
			}
			if !bytes.Equal(pt, payload) {
				t.Fatalf("message %d payload %x, want %x", i, pt, payload)
			}
			if i == 2 {
				if hh := init.Hash(); hex.EncodeToString(hh[:]) != v.HandshakeHash {
					t.Fatalf("handshake hash %x, want %s", hh, v.HandshakeHash)
				}
				if init.Hash() != resp.Hash() {
					t.Fatal("handshake hashes differ")
				}
				iSend, iRecv, _ = init.Split()
				rSend, rRecv, err = resp.Split()
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		irs, _ := init.PeerStatic()
		rrs, _ := resp.PeerStatic()
		if irs != key(t, v.RespStatic).Public || rrs != key(t, v.InitStatic).Public {
			t.Fatal("peer static keys not learned")
		}
	}
}

func pair(t *testing.T) (*Handshake, *Handshake, Key, Key) {
	t.Helper()
	ik, _ := GenerateKey()
	rk, _ := GenerateKey()
	return NewHandshake(Config{Initiator: true, Static: ik, Prologue: []byte("beacon")}),
		NewHandshake(Config{Static: rk, Prologue: []byte("beacon")}), ik, rk
}

func run(t *testing.T, init, resp *Handshake) {
	t.Helper()
	m1, err := init.WriteMessage(nil, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, _ := resp.WriteMessage(nil, []byte("two"))
	if _, err := init.ReadMessage(nil, m2); err != nil {
		t.Fatal(err)
	}
	m3, _ := init.WriteMessage(nil, []byte("three"))
	if _, err := resp.ReadMessage(nil, m3); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	init, resp, ik, rk := pair(t)
	if _, ok := resp.PeerStatic(); ok {
		t.Fatal("responder knows the peer before message 3")
	}
	run(t, init, resp)
	if !init.Done() || !resp.Done() {
		t.Fatal("not done")
	}
	if s, _ := init.PeerStatic(); s != rk.Public {
		t.Fatal("initiator learned the wrong key")
	}
	if s, _ := resp.PeerStatic(); s != ik.Public {
		t.Fatal("responder learned the wrong key")
	}
	is, ir, _ := init.Split()
	rs, rr, _ := resp.Split()
	for i := range 3 {
		ct, _ := is.Encrypt(nil, nil, []byte("hello"))
		if pt, err := rr.Decrypt(nil, nil, ct); err != nil || string(pt) != "hello" {
			t.Fatalf("round %d: %q %v", i, pt, err)
		}
		ct, _ = rs.Encrypt(nil, []byte("ad"), []byte("back"))
		if pt, err := ir.Decrypt(nil, []byte("ad"), ct); err != nil || string(pt) != "back" {
			t.Fatalf("round %d reply: %q %v", i, pt, err)
		}
	}
	// Explicit nonces decrypt out of order.
	c7, _ := is.EncryptNonce(nil, 7, nil, []byte("seven"))
	c5, _ := is.EncryptNonce(nil, 5, nil, []byte("five"))
	if pt, err := rr.DecryptNonce(nil, 7, nil, c7); err != nil || string(pt) != "seven" {
		t.Fatal(err)
	}
	if pt, err := rr.DecryptNonce(nil, 5, nil, c5); err != nil || string(pt) != "five" {
		t.Fatal(err)
	}
	if _, err := rr.DecryptNonce(nil, 6, nil, c5); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong nonce accepted")
	}
}

func TestTamperedMessages(t *testing.T) {
	for msg := 1; msg <= 3; msg++ {
		for _, pos := range []int{0, 31, -2, -1} {
			init, resp, _, _ := pair(t)
			a, b := init, resp
			var err error
			for i := 1; i <= msg; i++ {
				m, _ := a.WriteMessage(nil, []byte("payload"))
				if i == msg {
					p := pos
					if p < 0 {
						p += len(m)
					}
					m[p] ^= 1
				}
				_, err = b.ReadMessage(nil, m)
				a, b = b, a
			}
			// Flipping message 1 only alters the ephemeral key or clear payload;
			// the damage surfaces when message 2 fails to decrypt.
			if msg == 1 && err == nil {
				m2, _ := resp.WriteMessage(nil, nil)
				_, err = init.ReadMessage(nil, m2)
			}
			if err == nil {
				t.Errorf("message %d with byte %d flipped was accepted", msg, pos)
			}
		}
	}
}

func TestOrder(t *testing.T) {
	init, resp, _, _ := pair(t)
	if _, err := resp.WriteMessage(nil, nil); !errors.Is(err, ErrState) {
		t.Fatal("responder wrote first")
	}
	if _, err := init.ReadMessage(nil, make([]byte, 64)); !errors.Is(err, ErrState) {
		t.Fatal("initiator read first")
	}
	if _, _, err := init.Split(); !errors.Is(err, ErrState) {
		t.Fatal("split before the handshake finished")
	}
	run(t, init, resp)
	if _, err := init.WriteMessage(nil, nil); !errors.Is(err, ErrState) {
		t.Fatal("wrote after the handshake finished")
	}
}

func TestBadInput(t *testing.T) {
	_, resp, _, _ := pair(t)
	if _, err := resp.ReadMessage(nil, make([]byte, 10)); !errors.Is(err, ErrShort) {
		t.Fatalf("short message: %v", err)
	}
	if _, err := resp.ReadMessage(nil, make([]byte, 64)); !errors.Is(err, ErrState) {
		t.Fatal("a failed handshake kept going")
	}

	// A low-order ephemeral key (here zero) makes the DH output all zeros.
	_, resp, _, _ = pair(t)
	if _, err := resp.ReadMessage(nil, make([]byte, KeySize)); err != nil {
		t.Fatal(err)
	}
	if _, err := resp.WriteMessage(nil, nil); err == nil {
		t.Fatal("low-order peer key accepted")
	}

	_, resp, _, _ = pair(t)
	if _, err := resp.ReadMessage(nil, make([]byte, MaxMessage+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized message accepted")
	}
}

// FuzzHandshake feeds arbitrary bytes to each side at each step of the
// handshake; nothing may panic and nothing forged may complete it.
func FuzzHandshake(f *testing.F) {
	f.Add(uint8(0), make([]byte, 32))
	f.Add(uint8(1), make([]byte, 96))
	f.Add(uint8(2), make([]byte, 64))
	f.Add(uint8(1), []byte{})
	f.Fuzz(func(t *testing.T, step uint8, data []byte) {
		init, resp, _, _ := pair(t)
		step %= 3
		// Run honestly up to step, then deliver data in place of the real message.
		a, b := init, resp
		for i := range step {
			m, err := a.WriteMessage(nil, []byte{byte(i)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.ReadMessage(nil, m); err != nil {
				t.Fatal(err)
			}
			a, b = b, a
		}
		if _, err := b.ReadMessage(nil, data); err != nil {
			return
		}
		if step > 0 {
			t.Fatalf("forged message %d accepted", step+1)
		}
	})
}
