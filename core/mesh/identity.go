package mesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arjun-kshirsagar/beacon/core/noise"
)

// Fingerprint identifies a person: the hex SHA-256 of their Ed25519 public
// key. People verify each other by comparing fingerprints (or QR codes).
type Fingerprint string

// FingerprintOf returns the fingerprint of an Ed25519 public key.
func FingerprintOf(pub ed25519.PublicKey) Fingerprint {
	sum := sha256.Sum256(pub)
	return Fingerprint(hex.EncodeToString(sum[:]))
}

// Short returns the first 16 hex digits, for display.
func (f Fingerprint) Short() string { return string(f[:min(16, len(f))]) }

// Identity is a device's long-term keys: Ed25519 to sign, X25519 for Noise.
// It is generated on the device; there are no accounts.
type Identity struct {
	sign  ed25519.PrivateKey
	noise noise.Key
	proof []byte // signature binding the Noise key to the signing key
}

// IdentitySize is the length of a marshaled Identity.
const IdentitySize = ed25519.SeedSize + noise.KeySize

var errIdentity = errors.New("mesh: invalid identity")

// NewIdentity generates a fresh identity from crypto/rand.
func NewIdentity() (*Identity, error) {
	b := make([]byte, IdentitySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return UnmarshalIdentity(b)
}

// UnmarshalIdentity restores an identity saved with Marshal.
func UnmarshalIdentity(b []byte) (*Identity, error) {
	if len(b) != IdentitySize {
		return nil, errIdentity
	}
	nk, err := noise.KeyFromPrivate(b[ed25519.SeedSize:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIdentity, err)
	}
	id := &Identity{sign: ed25519.NewKeyFromSeed(b[:ed25519.SeedSize]), noise: nk}
	id.proof = ed25519.Sign(id.sign, staticProofMessage(nk.Public))
	return id, nil
}

// Marshal returns the private keys, for the platform to store securely.
func (id *Identity) Marshal() []byte {
	return append(id.sign.Seed(), id.noise.Private[:]...)
}

// Fingerprint returns the identity's fingerprint.
func (id *Identity) Fingerprint() Fingerprint { return FingerprintOf(id.SigningKey()) }

// SigningKey returns the Ed25519 public key.
func (id *Identity) SigningKey() ed25519.PublicKey { return id.sign.Public().(ed25519.PublicKey) }

// NoiseKey returns the X25519 public key used in Noise handshakes.
func (id *Identity) NoiseKey() [noise.KeySize]byte { return id.noise.Public }

// Wipe zeroes the private keys in memory. The identity is unusable after.
func (id *Identity) Wipe() {
	clear(id.sign)
	clear(id.noise.Private[:])
}

// staticProofMessage is what an identity signs to vouch for its Noise key.
func staticProofMessage(static [noise.KeySize]byte) []byte {
	return append([]byte("beacon-noise-static-v1\x00"), static[:]...)
}

// identityProof is sent inside the encrypted Noise handshake payloads: the
// signing key and its signature over the Noise static key.
func (id *Identity) identityProof() []byte {
	return append(append([]byte(nil), id.SigningKey()...), id.proof...)
}

// checkProof verifies a handshake payload against the static key the Noise
// handshake authenticated, returning the signing key.
func checkProof(payload []byte, static [noise.KeySize]byte) (ed25519.PublicKey, bool) {
	if len(payload) != ed25519.PublicKeySize+ed25519.SignatureSize {
		return nil, false
	}
	pub := ed25519.PublicKey(payload[:ed25519.PublicKeySize])
	if !ed25519.Verify(pub, staticProofMessage(static), payload[ed25519.PublicKeySize:]) {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}
