package offline

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Messages travel as mesh direct data, so they are end-to-end encrypted and
// authenticated by the sender's identity. See docs/protocol-spec.md.
const (
	msgRequest = 0x01 // "please let me fetch this file"
	msgOffer   = 0x02 // "join this group and fetch from these peers"

	minPassphrase = 8
	maxPassphrase = 63
	maxNetwork    = 32 // Wi-Fi SSIDs are at most 32 bytes
	maxOfferPeers = 16
)

var errMessage = errors.New("offline: malformed message")

type request struct {
	infoHash [20]byte
}

func (r request) encode() []byte {
	return append([]byte{msgRequest}, r.infoHash[:]...)
}

// offer tells a requester how to reach a swarm: the group's credentials and
// the peers in it.
type offer struct {
	infoHash   [20]byte
	network    string
	passphrase string
	peers      []netip.AddrPort // IPv4 only
}

func (o offer) encode() []byte {
	b := append([]byte{msgOffer}, o.infoHash[:]...)
	b = append(b, byte(len(o.network)))
	b = append(b, o.network...)
	b = append(b, byte(len(o.passphrase)))
	b = append(b, o.passphrase...)
	b = append(b, byte(len(o.peers)))
	for _, p := range o.peers {
		ip := p.Addr().As4()
		b = append(b, ip[:]...)
		b = append(b, byte(p.Port()>>8), byte(p.Port()))
	}
	return b
}

// parseMessage decodes a request or an offer, returning one of the two.
func parseMessage(b []byte) (*request, *offer, error) {
	if len(b) < 21 {
		return nil, nil, errMessage
	}
	var ih [20]byte
	copy(ih[:], b[1:])
	switch b[0] {
	case msgRequest:
		if len(b) != 21 {
			return nil, nil, errMessage
		}
		return &request{infoHash: ih}, nil, nil
	case msgOffer:
		o, err := parseOffer(ih, b[21:])
		return nil, o, err
	}
	return nil, nil, errMessage
}

func parseOffer(ih [20]byte, b []byte) (*offer, error) {
	o := &offer{infoHash: ih}
	field := func() (string, error) {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return "", errMessage
		}
		s := string(b[1 : 1+int(b[0])])
		b = b[1+int(b[0]):]
		return s, nil
	}
	var err error
	if o.network, err = field(); err != nil {
		return nil, err
	}
	if o.passphrase, err = field(); err != nil {
		return nil, err
	}
	if err := checkCredentials(o.network, o.passphrase); err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, errMessage
	}
	n := int(b[0])
	b = b[1:]
	if n == 0 || n > maxOfferPeers || len(b) != 6*n {
		return nil, fmt.Errorf("%w: %d peers in %d bytes", errMessage, n, len(b))
	}
	for i := range n {
		e := b[6*i:]
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte(e[:4])), uint16(e[4])<<8|uint16(e[5]))
		if !addr.Addr().IsPrivate() || addr.Port() == 0 {
			return nil, fmt.Errorf("%w: peer %v", errMessage, addr)
		}
		o.peers = append(o.peers, addr)
	}
	return o, nil
}

// checkCredentials accepts a Wi-Fi Direct group name and WPA2 passphrase.
func checkCredentials(network, passphrase string) error {
	if !strings.HasPrefix(network, "DIRECT-") || len(network) < 9 || len(network) > maxNetwork {
		return fmt.Errorf("%w: network %q", errMessage, network)
	}
	if len(passphrase) < minPassphrase || len(passphrase) > maxPassphrase {
		return fmt.Errorf("%w: passphrase length", errMessage)
	}
	for _, s := range []string{network, passphrase} {
		for _, r := range s {
			if r < 0x21 || r > 0x7e {
				return fmt.Errorf("%w: credentials must be printable ASCII", errMessage)
			}
		}
	}
	return nil
}
