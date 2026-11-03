package mesh

import "errors"

// Link framing: a packet larger than a link's MTU is split into frames, each
// with a one-byte header. Frames on a link arrive in order or not at all, so
// a start and an end bit are enough to rebuild packets and to resynchronise
// after a lost frame.
const (
	frameStart = 0x01
	frameEnd   = 0x02
	// MinMTU is the smallest link MTU the mesh works over.
	MinMTU = 20
)

var errFrame = errors.New("mesh: bad frame sequence")

// fragment splits packet into frames of at most mtu bytes.
func fragment(packet []byte, mtu int) [][]byte {
	chunk := mtu - 1
	var frames [][]byte
	for i := 0; i < len(packet) || i == 0; i += chunk {
		end := min(i+chunk, len(packet))
		var h byte
		if i == 0 {
			h |= frameStart
		}
		if end == len(packet) {
			h |= frameEnd
		}
		f := make([]byte, 0, 1+end-i)
		frames = append(frames, append(append(f, h), packet[i:end]...))
	}
	return frames
}

// assembler rebuilds packets from one link's frames. It never holds more than
// MaxPacket bytes.
type assembler struct {
	buf    []byte
	active bool
}

// add takes the next frame and returns a whole packet when one completes.
// After an error the assembler is ready for the next start frame.
func (a *assembler) add(frame []byte) ([]byte, error) {
	if len(frame) == 0 || frame[0]&^(frameStart|frameEnd) != 0 {
		a.reset()
		return nil, errFrame
	}
	h, data := frame[0], frame[1:]
	if h&frameStart != 0 {
		// A start while a packet is in progress means its tail was lost;
		// the partial packet is dropped.
		a.buf, a.active = a.buf[:0], true
	} else if !a.active {
		return nil, errFrame
	}
	if len(a.buf)+len(data) > MaxPacket {
		a.reset()
		return nil, errFrame
	}
	a.buf = append(a.buf, data...)
	if h&frameEnd == 0 {
		return nil, nil
	}
	p := append([]byte(nil), a.buf...)
	a.reset()
	return p, nil
}

func (a *assembler) reset() {
	a.buf, a.active = a.buf[:0], false
}
