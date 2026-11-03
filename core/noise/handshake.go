package noise

import (
	"crypto/rand"
	"io"
)

// Config sets up one side of a handshake.
type Config struct {
	Initiator bool
	Static    Key    // this side's long-term key
	Prologue  []byte // data both sides must agree on, bound into the hash

	random io.Reader // ephemeral key source; crypto/rand unless a test sets it
}

// Handshake is the spec's HandshakeState for the XX pattern.
type Handshake struct {
	ss        symmetricState
	initiator bool
	s, e      Key
	rs, re    [KeySize]byte
	random    io.Reader
	step      int // messages processed so far, 0 to 3
	failed    bool
}

// NewHandshake starts a handshake.
func NewHandshake(cfg Config) *Handshake {
	h := &Handshake{initiator: cfg.Initiator, s: cfg.Static, random: cfg.random}
	if h.random == nil {
		h.random = rand.Reader
	}
	h.ss.init(ProtocolName)
	h.ss.mixHash(cfg.Prologue)
	return h
}

// Done reports whether all three messages have been exchanged.
func (h *Handshake) Done() bool { return h.step == 3 }

// writeTurn reports whether the next message is ours to write.
func (h *Handshake) writeTurn() bool { return (h.step%2 == 0) == h.initiator }

// PeerStatic returns the peer's static public key once it has been received:
// after message 2 for the initiator, after message 3 for the responder.
func (h *Handshake) PeerStatic() ([KeySize]byte, bool) {
	if h.initiator && h.step >= 2 || !h.initiator && h.step == 3 {
		return h.rs, true
	}
	return [KeySize]byte{}, false
}

// Hash returns the handshake hash, which both sides share once done and which
// can bind application data (such as signatures) to this session.
func (h *Handshake) Hash() [32]byte { return h.ss.h }

// Split returns the transport cipher states once the handshake is done:
// send encrypts our messages and recv decrypts the peer's.
func (h *Handshake) Split() (send, recv *CipherState, err error) {
	if !h.Done() || h.failed {
		return nil, nil, ErrState
	}
	c1, c2 := h.ss.split()
	if h.initiator {
		return c1, c2, nil
	}
	return c2, c1, nil
}

// WriteMessage appends the next handshake message, carrying payload, to out.
// Payloads in the first message are sent in the clear; later ones are encrypted.
func (h *Handshake) WriteMessage(out, payload []byte) ([]byte, error) {
	if h.failed || h.Done() || !h.writeTurn() {
		return nil, ErrState
	}
	start := len(out)
	out, err := h.write(out, payload)
	if err != nil {
		h.failed = true
		return nil, err
	}
	if len(out)-start > MaxMessage {
		h.failed = true
		return nil, ErrTooLarge
	}
	h.step++
	return out, nil
}

func (h *Handshake) write(out, payload []byte) ([]byte, error) {
	var err error
	switch h.step {
	case 0: // -> e
		if err = h.newEphemeral(); err != nil {
			return nil, err
		}
		out = h.writeE(out)
	case 1: // <- e, ee, s, es
		if err = h.newEphemeral(); err != nil {
			return nil, err
		}
		out = h.writeE(out)
		if err = h.mixDH(h.e, h.re); err != nil {
			return nil, err
		}
		if out, err = h.ss.encryptAndHash(out, h.s.Public[:]); err != nil {
			return nil, err
		}
		if err = h.mixDH(h.s, h.re); err != nil {
			return nil, err
		}
	case 2: // -> s, se
		if out, err = h.ss.encryptAndHash(out, h.s.Public[:]); err != nil {
			return nil, err
		}
		if err = h.mixDH(h.s, h.re); err != nil {
			return nil, err
		}
	}
	return h.ss.encryptAndHash(out, payload)
}

// ReadMessage processes the peer's next handshake message and appends its
// payload to out. A failed read ends the handshake.
func (h *Handshake) ReadMessage(out, msg []byte) ([]byte, error) {
	if h.failed || h.Done() || h.writeTurn() {
		return nil, ErrState
	}
	if len(msg) > MaxMessage {
		h.failed = true
		return nil, ErrTooLarge
	}
	out, err := h.read(out, msg)
	if err != nil {
		h.failed = true
		return nil, err
	}
	h.step++
	return out, nil
}

func (h *Handshake) read(out, msg []byte) ([]byte, error) {
	var err error
	switch h.step {
	case 0: // -> e
		if msg, err = h.readE(msg); err != nil {
			return nil, err
		}
	case 1: // <- e, ee, s, es
		if msg, err = h.readE(msg); err != nil {
			return nil, err
		}
		if err = h.mixDH(h.e, h.re); err != nil {
			return nil, err
		}
		if msg, err = h.readS(msg); err != nil {
			return nil, err
		}
		if err = h.mixDH(h.e, h.rs); err != nil {
			return nil, err
		}
	case 2: // -> s, se
		if msg, err = h.readS(msg); err != nil {
			return nil, err
		}
		if err = h.mixDH(h.e, h.rs); err != nil {
			return nil, err
		}
	}
	return h.ss.decryptAndHash(out, msg)
}

func (h *Handshake) newEphemeral() error {
	e, err := generateKey(h.random)
	h.e = e
	return err
}

func (h *Handshake) writeE(out []byte) []byte {
	h.ss.mixHash(h.e.Public[:])
	return append(out, h.e.Public[:]...)
}

func (h *Handshake) readE(msg []byte) ([]byte, error) {
	if len(msg) < KeySize {
		return nil, ErrShort
	}
	copy(h.re[:], msg)
	h.ss.mixHash(h.re[:])
	return msg[KeySize:], nil
}

// readS reads the peer's static key, encrypted because a key is always set
// by the time XX sends s.
func (h *Handshake) readS(msg []byte) ([]byte, error) {
	n := KeySize + Overhead
	if len(msg) < n {
		return nil, ErrShort
	}
	rs, err := h.ss.decryptAndHash(nil, msg[:n])
	if err != nil {
		return nil, err
	}
	copy(h.rs[:], rs)
	return msg[n:], nil
}

func (h *Handshake) mixDH(priv Key, pub [KeySize]byte) error {
	shared, err := dh(priv.Private, pub)
	if err != nil {
		return err
	}
	h.ss.mixKey(shared)
	return nil
}
