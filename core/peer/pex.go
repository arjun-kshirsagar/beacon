package peer

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

// ExtPEX is the extension name for peer exchange (BEP 11).
const ExtPEX = "ut_pex"

// MaxPEXPeers bounds the added and dropped lists in one PEX message, in each
// direction; BEP 11 asks senders to stay within it.
const MaxPEXPeers = 50

// PEX flags describe an added peer.
const (
	PEXEncryption = 0x01 // prefers encryption
	PEXSeed       = 0x02 // is a seed
	PEXUTP        = 0x04 // supports uTP
	PEXHolepunch  = 0x08 // supports the holepunch extension
	PEXReachable  = 0x10 // accepted an outgoing connection
)

// PEX is a peer exchange message: peers the sender connected to and
// disconnected from since its last message to us.
type PEX struct {
	Added   []netip.AddrPort
	Flags   []byte // one per Added entry
	Dropped []netip.AddrPort
}

// Encode returns the bencoded message body.
func (p PEX) Encode() []byte {
	var added4, flags4, added6, flags6, dropped4, dropped6 []byte
	for i, a := range p.Added {
		var f byte
		if i < len(p.Flags) {
			f = p.Flags[i]
		}
		if a.Addr().Unmap().Is4() {
			added4 = appendCompact(added4, a)
			flags4 = append(flags4, f)
		} else {
			added6 = appendCompact(added6, a)
			flags6 = append(flags6, f)
		}
	}
	for _, a := range p.Dropped {
		if a.Addr().Unmap().Is4() {
			dropped4 = appendCompact(dropped4, a)
		} else {
			dropped6 = appendCompact(dropped6, a)
		}
	}
	b, _ := bencode.Encode(map[string]any{
		"added": added4, "added.f": flags4, "dropped": dropped4,
		"added6": added6, "added6.f": flags6, "dropped6": dropped6,
	})
	return b
}

func appendCompact(b []byte, a netip.AddrPort) []byte {
	if ip := a.Addr().Unmap(); ip.Is4() {
		v := ip.As4()
		b = append(b, v[:]...)
	} else {
		v := ip.As16()
		b = append(b, v[:]...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port())
}

// ParsePEX parses a PEX message body. Lists beyond MaxPEXPeers are truncated and
// unusable addresses (port 0, unspecified, multicast) are dropped, keeping each
// flag with its peer.
func ParsePEX(body []byte) (PEX, error) {
	v, err := bencode.Decode(body)
	if err != nil {
		return PEX{}, fmt.Errorf("%w: pex: %w", ErrMalformed, err)
	}
	d, ok := v.(map[string]any)
	if !ok {
		return PEX{}, fmt.Errorf("%w: pex message is not a dictionary", ErrMalformed)
	}
	var p PEX
	addPeers := func(key, flagKey string, size int) error {
		s, _ := d[key].(string)
		if len(s)%size != 0 {
			return fmt.Errorf("%w: %s is %d bytes", ErrMalformed, key, len(s))
		}
		flags, _ := d[flagKey].(string)
		for i := 0; i < len(s)/size && len(p.Added) < MaxPEXPeers; i++ {
			a, ok := parseCompact(s[i*size : (i+1)*size])
			if !ok {
				continue
			}
			var f byte
			if i < len(flags) {
				f = flags[i]
			}
			p.Added = append(p.Added, a)
			p.Flags = append(p.Flags, f)
		}
		return nil
	}
	dropPeers := func(key string, size int) error {
		s, _ := d[key].(string)
		if len(s)%size != 0 {
			return fmt.Errorf("%w: %s is %d bytes", ErrMalformed, key, len(s))
		}
		for i := 0; i < len(s)/size && len(p.Dropped) < MaxPEXPeers; i++ {
			if a, ok := parseCompact(s[i*size : (i+1)*size]); ok {
				p.Dropped = append(p.Dropped, a)
			}
		}
		return nil
	}
	for _, err := range []error{
		addPeers("added", "added.f", 6), addPeers("added6", "added6.f", 18),
		dropPeers("dropped", 6), dropPeers("dropped6", 18),
	} {
		if err != nil {
			return PEX{}, err
		}
	}
	return p, nil
}

func parseCompact(s string) (netip.AddrPort, bool) {
	b := []byte(s)
	ip, ok := netip.AddrFromSlice(b[:len(b)-2])
	if !ok {
		return netip.AddrPort{}, false
	}
	a := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(b[len(b)-2:]))
	if a.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, false
	}
	return a, true
}
