package torrent

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	maxMagnetLen   = 8 << 10
	maxMagnetItems = 64 // trackers or peers kept from one link
)

// ErrMagnet reports an unusable magnet link.
var ErrMagnet = errors.New("torrent: invalid magnet link")

// Magnet is a parsed BitTorrent magnet link (BEP 9).
type Magnet struct {
	InfoHash [HashSize]byte
	Name     string   // dn: display name, a hint only
	Trackers []string // tr
	Peers    []string // x.pe: host:port of peers to try
}

// ParseMagnet parses a magnet:?xt=urn:btih:... link.
func ParseMagnet(uri string) (*Magnet, error) {
	if len(uri) > maxMagnetLen {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrMagnet, maxMagnetLen)
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "magnet" {
		return nil, fmt.Errorf("%w: not a magnet URI", ErrMagnet)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMagnet, err)
	}
	m := &Magnet{Name: q.Get("dn")}
	found := false
	for _, xt := range q["xt"] {
		hash, ok := strings.CutPrefix(xt, "urn:btih:")
		if !ok {
			continue
		}
		var b []byte
		switch len(hash) {
		case 40:
			b, err = hex.DecodeString(hash)
		case 32:
			b, err = base32.StdEncoding.DecodeString(strings.ToUpper(hash))
		default:
			err = errors.New("bad length")
		}
		if err != nil {
			return nil, fmt.Errorf("%w: info-hash %q: %v", ErrMagnet, hash, err)
		}
		copy(m.InfoHash[:], b)
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("%w: no urn:btih info-hash", ErrMagnet)
	}
	for _, tr := range q["tr"] {
		if t, err := url.Parse(tr); err == nil && t.Scheme != "" && len(m.Trackers) < maxMagnetItems {
			m.Trackers = append(m.Trackers, tr)
		}
	}
	for _, pe := range q["x.pe"] {
		if pe != "" && len(m.Peers) < maxMagnetItems {
			m.Peers = append(m.Peers, pe)
		}
	}
	return m, nil
}

// String encodes the magnet link.
func (m *Magnet) String() string {
	q := url.Values{}
	if m.Name != "" {
		q.Set("dn", m.Name)
	}
	for _, tr := range m.Trackers {
		q.Add("tr", tr)
	}
	for _, pe := range m.Peers {
		q.Add("x.pe", pe)
	}
	s := "magnet:?xt=urn:btih:" + hex.EncodeToString(m.InfoHash[:])
	if enc := q.Encode(); enc != "" {
		s += "&" + enc
	}
	return s
}
