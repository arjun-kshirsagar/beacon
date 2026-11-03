package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// MaxStreamMTU is the largest frame a stream link can carry.
const MaxStreamMTU = 65535

// StreamLink carries frames over a stream connection such as TCP, each
// prefixed with its length as a big-endian uint16. It lets the mesh run over
// LAN or Wi-Fi Direct connections as well as BLE.
type StreamLink struct {
	conn net.Conn
	mtu  int
	peer string
	wmu  sync.Mutex
	buf  []byte
}

// NewStreamLink wraps conn. Frames over mtu bytes are refused in both
// directions; a peer sending one is cut off.
func NewStreamLink(conn net.Conn, mtu int, peer string) *StreamLink {
	mtu = min(mtu, MaxStreamMTU)
	return &StreamLink{conn: conn, mtu: mtu, peer: peer, buf: make([]byte, mtu)}
}

// ReadFrame reads the next frame. It must not be called concurrently with
// itself.
func (l *StreamLink) ReadFrame() ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(l.conn, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 0 || n > l.mtu {
		return nil, fmt.Errorf("transport: peer sent a %d-byte frame (MTU %d)", n, l.mtu)
	}
	if _, err := io.ReadFull(l.conn, l.buf[:n]); err != nil {
		return nil, err
	}
	return append([]byte(nil), l.buf[:n]...), nil
}

// WriteFrame writes one frame.
func (l *StreamLink) WriteFrame(frame []byte) error {
	if len(frame) == 0 || len(frame) > l.mtu {
		return ErrFrameTooLarge
	}
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(frame)), uint16(len(frame)))
	b = append(b, frame...)
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_, err := l.conn.Write(b)
	return err
}

func (l *StreamLink) MTU() int     { return l.mtu }
func (l *StreamLink) Peer() string { return l.peer }
func (l *StreamLink) Close() error { return l.conn.Close() }
