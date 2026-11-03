package noise

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ProtocolName names the one protocol this package speaks.
	ProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"
	// MaxMessage is the largest Noise message, handshake or transport.
	MaxMessage = 65535
	// KeySize is the size of X25519 keys.
	KeySize = 32
	// Overhead is the authentication tag added to each encrypted payload.
	Overhead = chacha20poly1305.Overhead

	hashLen = sha256.Size
)

var (
	// ErrDecrypt reports a message that failed authentication.
	ErrDecrypt = errors.New("noise: message authentication failed")
	// ErrShort reports a handshake message too short for its pattern.
	ErrShort = errors.New("noise: message too short")
	// ErrTooLarge reports a message over MaxMessage.
	ErrTooLarge = errors.New("noise: message too large")
	// ErrState reports a call out of order, such as writing when it is the
	// peer's turn or reading after the handshake finished.
	ErrState = errors.New("noise: handshake out of order")
	// ErrNonce reports an exhausted or reserved nonce.
	ErrNonce = errors.New("noise: nonce exhausted")
)

// Key is an X25519 key pair.
type Key struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKey returns a fresh key pair from crypto/rand.
func GenerateKey() (Key, error) {
	return generateKey(rand.Reader)
}

func generateKey(r io.Reader) (Key, error) {
	var priv [KeySize]byte
	if _, err := io.ReadFull(r, priv[:]); err != nil {
		return Key{}, fmt.Errorf("noise: generating key: %w", err)
	}
	return KeyFromPrivate(priv[:])
}

// KeyFromPrivate derives the key pair for a 32-byte X25519 private key.
func KeyFromPrivate(priv []byte) (Key, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return Key{}, fmt.Errorf("noise: %w", err)
	}
	var k Key
	copy(k.Private[:], priv)
	copy(k.Public[:], sk.PublicKey().Bytes())
	return k, nil
}

// dh computes X25519(priv, pub). It fails on low-order public keys, whose
// shared secret is all zeros.
func dh(priv, pub [KeySize]byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		return nil, err
	}
	out, err := sk.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("noise: bad public key: %w", err)
	}
	return out, nil
}

// CipherState encrypts with one key and a counter nonce (spec section 5.1).
type CipherState struct {
	aead cipher.AEAD
	n    uint64
}

func newCipherState(k []byte) *CipherState {
	aead, _ := chacha20poly1305.New(k) // k is always 32 bytes
	return &CipherState{aead: aead}
}

func (c *CipherState) hasKey() bool { return c != nil && c.aead != nil }

func nonce(n uint64) []byte {
	var b [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b[:]
}

// Encrypt appends the encryption of plaintext with associated data ad to out,
// using and then advancing the internal nonce.
func (c *CipherState) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if c.n == math.MaxUint64 {
		return nil, ErrNonce
	}
	out, err := c.EncryptNonce(out, c.n, ad, plaintext)
	if err == nil {
		c.n++
	}
	return out, err
}

// Decrypt appends the decryption of ciphertext to out, using and then
// advancing the internal nonce. The nonce does not advance on failure.
func (c *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if c.n == math.MaxUint64 {
		return nil, ErrNonce
	}
	out, err := c.DecryptNonce(out, c.n, ad, ciphertext)
	if err == nil {
		c.n++
	}
	return out, err
}

// EncryptNonce encrypts with an explicit nonce n and leaves the internal
// counter alone. It is for transports that may reorder or drop messages and
// carry the nonce beside the ciphertext; the caller must never reuse n.
func (c *CipherState) EncryptNonce(out []byte, n uint64, ad, plaintext []byte) ([]byte, error) {
	if n == math.MaxUint64 {
		return nil, ErrNonce
	}
	if len(plaintext)+Overhead > MaxMessage {
		return nil, ErrTooLarge
	}
	return c.aead.Seal(out, nonce(n), plaintext, ad), nil
}

// DecryptNonce decrypts with an explicit nonce n. The caller is responsible
// for rejecting replayed nonces.
func (c *CipherState) DecryptNonce(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	if n == math.MaxUint64 {
		return nil, ErrNonce
	}
	if len(ciphertext) > MaxMessage {
		return nil, ErrTooLarge
	}
	out, err := c.aead.Open(out, nonce(n), ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// symmetricState is the spec's SymmetricState (section 5.2).
type symmetricState struct {
	cs *CipherState
	ck [hashLen]byte
	h  [hashLen]byte
}

func (s *symmetricState) init(name string) {
	if len(name) <= hashLen {
		copy(s.h[:], name)
	} else {
		s.h = sha256.Sum256([]byte(name))
	}
	s.ck = s.h
}

func (s *symmetricState) mixHash(data []byte) {
	d := sha256.New()
	d.Write(s.h[:])
	d.Write(data)
	d.Sum(s.h[:0])
}

func (s *symmetricState) mixKey(ikm []byte) {
	ck, k := hkdf2(s.ck[:], ikm)
	s.ck = ck
	s.cs = newCipherState(k[:])
}

func (s *symmetricState) encryptAndHash(out, plaintext []byte) ([]byte, error) {
	start := len(out)
	if s.cs.hasKey() {
		var err error
		if out, err = s.cs.Encrypt(out, s.h[:], plaintext); err != nil {
			return nil, err
		}
	} else {
		out = append(out, plaintext...)
	}
	s.mixHash(out[start:])
	return out, nil
}

func (s *symmetricState) decryptAndHash(out, ciphertext []byte) ([]byte, error) {
	var err error
	if s.cs.hasKey() {
		out, err = s.cs.Decrypt(out, s.h[:], ciphertext)
	} else {
		out = append(out, ciphertext...)
	}
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return out, nil
}

func (s *symmetricState) split() (*CipherState, *CipherState) {
	k1, k2 := hkdf2(s.ck[:], nil)
	return newCipherState(k1[:]), newCipherState(k2[:])
}

func hmacHash(key []byte, data ...[]byte) [hashLen]byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	var out [hashLen]byte
	m.Sum(out[:0])
	return out
}

// hkdf2 is the spec's HKDF with two outputs (section 4.3).
func hkdf2(ck, ikm []byte) (o1, o2 [hashLen]byte) {
	temp := hmacHash(ck, ikm)
	o1 = hmacHash(temp[:], []byte{1})
	o2 = hmacHash(temp[:], o1[:], []byte{2})
	return o1, o2
}
