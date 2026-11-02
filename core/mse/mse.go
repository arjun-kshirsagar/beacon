// Package mse implements BitTorrent Message Stream Encryption (MSE, also called
// Protocol Encryption): a Diffie-Hellman key exchange followed by an RC4 stream,
// keyed by the torrent's info-hash.
//
// MSE exists to get past ISPs and peers that block or refuse plaintext
// BitTorrent. It is obfuscation, not security: RC4 is broken, the exchange is
// unauthenticated, and big.Int exponentiation is not constant time. Beacon's
// real confidentiality comes from Noise; this package is for interoperability.
package mse

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
)

// Method is a crypto_provide / crypto_select bit set.
type Method uint32

const (
	Plaintext Method = 0x01 // obfuscated handshake, then plaintext payload
	RC4       Method = 0x02 // the whole stream is RC4-encrypted
)

const (
	keyLen    = 96  // bytes in a DH public key and the shared secret
	maxPad    = 512 // longest padding the spec allows
	maxIA     = 4096
	privBits  = 160
	discard   = 1024 // RC4 keystream bytes dropped before use
	handshake = 20   // bytes Detect reads to tell plaintext from MSE
)

var (
	// ErrHandshake reports an MSE handshake that did not follow the protocol.
	ErrHandshake = errors.New("mse: handshake failed")
	// ErrUnknownTorrent reports an initiator asking for an info-hash we do not serve.
	ErrUnknownTorrent = errors.New("mse: unknown info-hash")
	// ErrNoCommonMethod reports that the two sides allow no common method.
	ErrNoCommonMethod = errors.New("mse: no common crypto method")
)

var (
	prime = mustPrime("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563")
	two   = big.NewInt(2)
	vc    = make([]byte, 8) // verification constant: eight zero bytes
)

func mustPrime(h string) *big.Int {
	p, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("mse: bad prime constant")
	}
	return p
}

func hash(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

type dhKey struct {
	priv *big.Int
	pub  []byte
}

func newKey() (*dhKey, error) {
	priv, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), privBits))
	if err != nil {
		return nil, err
	}
	return &dhKey{priv: priv, pub: pad96(new(big.Int).Exp(two, priv, prime))}, nil
}

// secret computes S from the peer's public key, rejecting degenerate keys that
// would force a predictable secret.
func (k *dhKey) secret(peerPub []byte) ([]byte, error) {
	y := new(big.Int).SetBytes(peerPub)
	pMinus1 := new(big.Int).Sub(prime, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("%w: degenerate public key", ErrHandshake)
	}
	return pad96(new(big.Int).Exp(y, k.priv, prime)), nil
}

func pad96(x *big.Int) []byte {
	b := make([]byte, keyLen)
	return x.FillBytes(b)
}

func randomPad() ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(maxPad+1))
	if err != nil {
		return nil, err
	}
	p := make([]byte, n.Int64())
	_, err = rand.Read(p)
	return p, err
}

func newCipher(name string, s, skey []byte) *rc4.Cipher {
	c, _ := rc4.NewCipher(hash([]byte(name), s, skey)) // a 20-byte key is always valid
	junk := make([]byte, discard)
	c.XORKeyStream(junk, junk)
	return c
}

// scan reads from r until the last len(want) bytes equal want, giving up after
// limit bytes. It finds the end of the peer's random padding.
func scan(r io.Reader, want []byte, limit int) error {
	window := make([]byte, 0, len(want))
	one := make([]byte, 1)
	for range limit {
		if _, err := io.ReadFull(r, one); err != nil {
			return err
		}
		if len(window) == len(want) {
			copy(window, window[1:])
			window = window[:len(want)-1]
		}
		window = append(window, one[0])
		if bytes.Equal(window, want) {
			return nil
		}
	}
	return fmt.Errorf("%w: synchronization marker not found", ErrHandshake)
}

func readU16(r io.Reader) (int, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b[:])), nil
}

// decryptReader decrypts everything read through it.
type decryptReader struct {
	r io.Reader
	c *rc4.Cipher
}

func (d decryptReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.c.XORKeyStream(p[:n], p[:n])
	return n, err
}

// Initiate runs the initiator side of the handshake on conn for infoHash,
// offering the methods in provide. It returns the connection to use from now on
// and the method the peer selected.
func Initiate(conn net.Conn, infoHash [20]byte, provide Method) (net.Conn, Method, error) {
	return initiate(conn, infoHash, provide, nil)
}

// initiate is Initiate with an initial payload, which other clients use to send
// their BitTorrent handshake early.
func initiate(conn net.Conn, infoHash [20]byte, provide Method, ia []byte) (net.Conn, Method, error) {
	key, err := newKey()
	if err != nil {
		return nil, 0, err
	}
	padA, err := randomPad()
	if err != nil {
		return nil, 0, err
	}
	if _, err := conn.Write(append(key.pub, padA...)); err != nil {
		return nil, 0, err
	}

	yb := make([]byte, keyLen)
	if _, err := io.ReadFull(conn, yb); err != nil {
		return nil, 0, fmt.Errorf("%w: reading key: %w", ErrHandshake, err)
	}
	s, err := key.secret(yb)
	if err != nil {
		return nil, 0, err
	}
	skey := infoHash[:]
	encA := newCipher("keyA", s, skey)
	decB := newCipher("keyB", s, skey)

	// HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC,
	// crypto_provide, len(PadC)=0, len(IA), IA).
	msg := hash([]byte("req1"), s)
	req2, req3 := hash([]byte("req2"), skey), hash([]byte("req3"), s)
	for i := range req2 {
		msg = append(msg, req2[i]^req3[i])
	}
	plain := append(append([]byte(nil), vc...), 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(plain[8:], uint32(provide))
	binary.BigEndian.PutUint16(plain[14:], uint16(len(ia)))
	plain = append(plain, ia...)
	enc := make([]byte, len(plain))
	encA.XORKeyStream(enc, plain)
	if _, err := conn.Write(append(msg, enc...)); err != nil {
		return nil, 0, err
	}

	// Find the end of PadB by looking for VC encrypted under keyB.
	wantVC := make([]byte, len(vc))
	decB.XORKeyStream(wantVC, vc)
	if err := scan(conn, wantVC, maxPad+len(vc)); err != nil {
		return nil, 0, err
	}
	dr := decryptReader{r: conn, c: decB}
	var sel [4]byte
	if _, err := io.ReadFull(dr, sel[:]); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	method := Method(binary.BigEndian.Uint32(sel[:]))
	if method != Plaintext && method != RC4 || method&provide == 0 {
		return nil, 0, fmt.Errorf("%w: peer selected method %#x", ErrHandshake, uint32(method))
	}
	padD, err := readU16(dr)
	if err != nil || padD > maxPad {
		return nil, 0, fmt.Errorf("%w: bad padD length", ErrHandshake)
	}
	if _, err := io.CopyN(io.Discard, dr, int64(padD)); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if method == Plaintext {
		return conn, method, nil
	}
	return &Conn{Conn: conn, enc: encA, dec: decB}, method, nil
}

// Accept runs the responder side of the handshake on conn. infoHashes lists the
// torrents we serve; allow is the set of methods we accept. It returns the
// connection to use, the info-hash the initiator asked for, and the method
// chosen. Any initial payload the initiator sent is returned first by reads.
func Accept(conn net.Conn, infoHashes [][20]byte, allow Method) (net.Conn, [20]byte, Method, error) {
	var none [20]byte
	ya := make([]byte, keyLen)
	if _, err := io.ReadFull(conn, ya); err != nil {
		return nil, none, 0, fmt.Errorf("%w: reading key: %w", ErrHandshake, err)
	}
	key, err := newKey()
	if err != nil {
		return nil, none, 0, err
	}
	s, err := key.secret(ya)
	if err != nil {
		return nil, none, 0, err
	}
	padB, err := randomPad()
	if err != nil {
		return nil, none, 0, err
	}
	if _, err := conn.Write(append(key.pub, padB...)); err != nil {
		return nil, none, 0, err
	}

	if err := scan(conn, hash([]byte("req1"), s), maxPad+sha1.Size); err != nil {
		return nil, none, 0, err
	}
	var mixed [sha1.Size]byte
	if _, err := io.ReadFull(conn, mixed[:]); err != nil {
		return nil, none, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	req3 := hash([]byte("req3"), s)
	var infoHash [20]byte
	found := false
	for _, ih := range infoHashes {
		req2 := hash([]byte("req2"), ih[:])
		match := true
		for i := range req2 {
			if req2[i]^req3[i] != mixed[i] {
				match = false
				break
			}
		}
		if match {
			infoHash, found = ih, true
			break
		}
	}
	if !found {
		return nil, none, 0, ErrUnknownTorrent
	}
	decA := newCipher("keyA", s, infoHash[:])
	encB := newCipher("keyB", s, infoHash[:])
	dr := decryptReader{r: conn, c: decA}

	var head [12]byte // VC and crypto_provide
	if _, err := io.ReadFull(dr, head[:]); err != nil {
		return nil, none, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if !bytes.Equal(head[:8], vc) {
		return nil, none, 0, fmt.Errorf("%w: bad verification constant", ErrHandshake)
	}
	provide := Method(binary.BigEndian.Uint32(head[8:]))
	padC, err := readU16(dr)
	if err != nil || padC > maxPad {
		return nil, none, 0, fmt.Errorf("%w: bad padC length", ErrHandshake)
	}
	if _, err := io.CopyN(io.Discard, dr, int64(padC)); err != nil {
		return nil, none, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	iaLen, err := readU16(dr)
	if err != nil || iaLen > maxIA {
		return nil, none, 0, fmt.Errorf("%w: bad IA length", ErrHandshake)
	}
	ia := make([]byte, iaLen)
	if _, err := io.ReadFull(dr, ia); err != nil {
		return nil, none, 0, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	var method Method
	switch common := provide & allow; {
	case common&RC4 != 0:
		method = RC4
	case common&Plaintext != 0:
		method = Plaintext
	default:
		return nil, none, 0, ErrNoCommonMethod
	}
	// ENCRYPT(VC, crypto_select, len(padD)=0).
	reply := append(append([]byte(nil), vc...), 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(reply[8:], uint32(method))
	encB.XORKeyStream(reply, reply)
	if _, err := conn.Write(reply); err != nil {
		return nil, none, 0, err
	}
	out := &Conn{Conn: conn, prefix: ia}
	if method == RC4 {
		out.enc, out.dec = encB, decA
	}
	return out, infoHash, method, nil
}

// Detect reads the start of an incoming connection and reports whether it is an
// MSE handshake rather than a plaintext BitTorrent one. The returned connection
// replays the bytes Detect consumed.
func Detect(conn net.Conn) (net.Conn, bool, error) {
	head := make([]byte, handshake)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, false, err
	}
	plain := head[0] == 19 && string(head[1:]) == "BitTorrent protocol"
	return &Conn{Conn: conn, prefix: head}, !plain, nil
}

// Conn is a connection after an MSE handshake. With RC4 selected it encrypts
// writes and decrypts reads; either way it first returns any buffered prefix.
type Conn struct {
	net.Conn
	enc, dec *rc4.Cipher // nil for plaintext
	prefix   []byte      // already-decrypted bytes to return before reading Conn
	wmu      sync.Mutex
}

// Encrypted reports whether the stream is RC4-encrypted.
func (c *Conn) Encrypted() bool { return c.enc != nil }

func (c *Conn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	n, err := c.Conn.Read(p)
	if c.dec != nil {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.enc == nil {
		return c.Conn.Write(p)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}
