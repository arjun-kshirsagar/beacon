package engine

import (
	"errors"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/reputation"
)

// msgRate is how many control messages per second a peer may send. Piece and
// request messages are exempt: their volume is bounded by the transfer itself.
const msgRate = 200

// allowMessage applies a token bucket to control messages. The burst allows a
// have message for every piece, which some clients send instead of a bitfield.
func (pc *peerConn) allowMessage(m *peer.Message) bool {
	if m != nil && (m.ID == peer.MsgPiece || m.ID == peer.MsgRequest) {
		return true
	}
	burst := float64(pc.c.t.NumPieces() + msgRate)
	now := time.Now()
	if pc.lastFill.IsZero() {
		pc.tokens = burst
	} else {
		pc.tokens = min(burst, pc.tokens+now.Sub(pc.lastFill).Seconds()*msgRate)
	}
	pc.lastFill = now
	if pc.tokens < 1 {
		return false
	}
	pc.tokens--
	return true
}

// reportErr turns the error that ended a connection into a reputation event.
// Network failures and ordinary disagreements are not held against the peer.
func (c *Client) reportErr(key string, err error) {
	var e reputation.Event
	switch {
	case errors.Is(err, errFlood):
		e = reputation.Flood
	case errors.Is(err, errSnubbed):
		e = reputation.Snubbed
	case errors.Is(err, peer.ErrMalformed), errors.Is(err, peer.ErrTooLarge), errors.Is(err, ErrBadRequest):
		e = reputation.ProtocolViolation
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report(key, e)
}
