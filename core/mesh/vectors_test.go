package mesh

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// vectors are fixed encodings other implementations (the Android app among
// them) must reproduce. Ed25519 signatures are deterministic, so every field
// follows from the fixed keys and inputs.
type vectors struct {
	IdentityPrivate string   `json:"identity_private"`
	SigningPublic   string   `json:"signing_public"`
	NoisePublic     string   `json:"noise_public"`
	Fingerprint     string   `json:"fingerprint"`
	IdentityProof   string   `json:"identity_proof"`
	Announce        string   `json:"announce_packet"`
	Channel         string   `json:"channel_packet"`
	ChannelFrames23 []string `json:"channel_frames_mtu_23"`
	Handshake       string   `json:"handshake_packet"`
	EncryptedAD     string   `json:"encrypted_associated_data"`
	PaddedText      string   `json:"padded_plaintext"`
	Share           string   `json:"share_packet"`
	PaddedData      string   `json:"padded_data_plaintext"`
}

func buildVectors(t *testing.T) vectors {
	seed := make([]byte, IdentitySize)
	for i := range seed {
		seed[i] = byte(i)
	}
	id, err := UnmarshalIdentity(seed)
	if err != nil {
		t.Fatal(err)
	}
	base := func(typ Type, payload []byte) *Packet {
		return &Packet{Type: typ, TTL: MaxTTL, ID: PacketID{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
			Time: time.UnixMilli(1_767_225_600_000), Sender: PeerID{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58},
			Payload: payload}
	}
	ann := base(TypeAnnounce, announce{signKey: id.SigningKey(), noiseKey: id.NoiseKey(), nickname: "alice"}.encode())
	ann.Sign(id.sign)
	ch := base(TypeChannel, channelMessage{channel: "#general", text: "hello, mesh"}.encode())
	ch.Sign(id.sign)
	var frames []string
	for _, f := range fragment(ch.Encode(), 23) {
		frames = append(frames, hex.EncodeToString(f))
	}
	recipient := PeerID{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68}
	hs := base(TypeHandshake, append([]byte{hsStep1}, make([]byte, 32)...))
	hs.Recipient = &recipient
	enc := base(TypeEncrypted, nil)
	enc.Recipient = &recipient
	sh := base(TypeShare, sharePayload([20]byte{0x58, 0x9b, 0xd9, 0xd4}, "photos.bin", 5_000_000))
	sh.Sign(id.sign)
	noiseKey := id.NoiseKey()
	return vectors{
		IdentityPrivate: hex.EncodeToString(seed),
		SigningPublic:   hex.EncodeToString(id.SigningKey()),
		NoisePublic:     hex.EncodeToString(noiseKey[:]),
		Fingerprint:     string(id.Fingerprint()),
		IdentityProof:   hex.EncodeToString(id.identityProof()),
		Announce:        hex.EncodeToString(ann.Encode()),
		Channel:         hex.EncodeToString(ch.Encode()),
		ChannelFrames23: frames,
		Handshake:       hex.EncodeToString(hs.Encode()),
		EncryptedAD:     hex.EncodeToString(enc.header()),
		PaddedText:      hex.EncodeToString(padText("hi")),
		Share:           hex.EncodeToString(sh.Encode()),
		PaddedData:      hex.EncodeToString(padInner(innerData, []byte{0x01, 0x02})),
	}
}

func TestVectors(t *testing.T) {
	got := buildVectors(t)
	const path = "testdata/vectors.json"
	if *update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Fatalf("encodings differ from %s; if the wire format changed on purpose, update docs/protocol-spec.md, bump Version if needed, and run go test -update", path)
	}
	// The stored packets must also parse and verify.
	for _, h := range []string{want.Announce, want.Channel, want.Share} {
		b, _ := hex.DecodeString(h)
		p, err := ParsePacket(b)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(want.SigningPublic)
		if !p.Verify(pub) {
			t.Fatal("vector signature does not verify")
		}
	}
}
