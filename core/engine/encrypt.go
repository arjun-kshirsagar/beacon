package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/mse"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// Encryption is the policy for Message Stream Encryption with peers.
type Encryption int

const (
	// EncryptPrefer tries MSE on outgoing connections, falls back to plaintext
	// if the peer does not speak it, and accepts both kinds of incoming peer.
	EncryptPrefer Encryption = iota
	// EncryptRequire uses RC4-encrypted MSE only, in both directions.
	EncryptRequire
	// EncryptDisable uses plaintext only.
	EncryptDisable
)

// ParseEncryption parses "prefer", "require" or "off".
func ParseEncryption(s string) (Encryption, error) {
	switch s {
	case "prefer":
		return EncryptPrefer, nil
	case "require":
		return EncryptRequire, nil
	case "off":
		return EncryptDisable, nil
	}
	return 0, fmt.Errorf("engine: unknown encryption mode %q (want prefer, require or off)", s)
}

// mseTimeout bounds the MSE handshake, so a peer that neither answers nor hangs
// up cannot delay the plaintext fallback for long.
const mseTimeout = 10 * time.Second

// ErrPolicy reports a peer whose encryption choice our policy refuses.
var ErrPolicy = errors.New("engine: peer refused by encryption policy")

func (e Encryption) methods() mse.Method {
	if e == EncryptRequire {
		return mse.RC4
	}
	return mse.RC4 | mse.Plaintext
}

// secureDial connects to addr and, unless encryption is off, runs the MSE
// handshake. Under EncryptPrefer a failed handshake is retried in plaintext on
// a fresh connection, since peers without MSE close on the first bytes.
func secureDial(ctx context.Context, tr transport.Transport, addr string, infoHash [20]byte, enc Encryption) (net.Conn, bool, error) {
	dial := func() (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		return tr.Dial(dctx, addr)
	}
	conn, err := dial()
	if err != nil || enc == EncryptDisable {
		return conn, false, err
	}
	conn.SetDeadline(time.Now().Add(mseTimeout))
	sc, method, err := mse.Initiate(conn, infoHash, enc.methods())
	conn.SetDeadline(time.Time{})
	if err == nil {
		return sc, method == mse.RC4, nil
	}
	conn.Close()
	if enc == EncryptRequire || ctx.Err() != nil {
		return nil, false, err
	}
	conn, err = dial()
	return conn, false, err
}

// secureAccept detects whether an incoming peer speaks MSE, applies the policy,
// and completes the MSE handshake if it does.
func secureAccept(conn net.Conn, infoHash [20]byte, enc Encryption) (net.Conn, bool, error) {
	conn.SetDeadline(time.Now().Add(mseTimeout))
	defer conn.SetDeadline(time.Time{})
	dc, encrypted, err := mse.Detect(conn)
	if err != nil {
		return nil, false, err
	}
	switch {
	case !encrypted && enc == EncryptRequire:
		return nil, false, fmt.Errorf("%w: plaintext peer", ErrPolicy)
	case !encrypted:
		return dc, false, nil
	case enc == EncryptDisable:
		return nil, false, fmt.Errorf("%w: encrypted peer", ErrPolicy)
	}
	sc, _, method, err := mse.Accept(dc, [][20]byte{infoHash}, enc.methods())
	if err != nil {
		return nil, false, err
	}
	return sc, method == mse.RC4, nil
}
