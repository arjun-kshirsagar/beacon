package torrent

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

const (
	// HashSize is the size of a SHA-1 piece hash and of an info-hash.
	HashSize = sha1.Size
	// MaxPieceLength bounds the piece length a torrent may declare. Whole pieces
	// are held in memory while they are verified.
	MaxPieceLength = 64 << 20
)

// ErrInvalid reports a metainfo file that is well-formed bencode but not a valid
// torrent.
var ErrInvalid = errors.New("torrent: invalid metainfo")

// File is one file in a torrent. Path is relative to the download directory and
// always starts with the torrent's name, for single- and multi-file torrents
// alike.
type File struct {
	Path   []string
	Length int64
	Offset int64 // offset of the file's first byte in the torrent's data
}

// Torrent is a parsed metainfo file.
type Torrent struct {
	Announce     string
	AnnounceList [][]string // BEP 12 tiers
	InfoHash     [HashSize]byte
	Name         string
	PieceLength  int64
	Pieces       [][HashSize]byte
	Length       int64 // total length of all files
	Files        []File
	MultiFile    bool
	Private      bool
	InfoBytes    []byte // the info dictionary exactly as encoded; its SHA-1 is InfoHash
}

// NumPieces returns the number of pieces.
func (t *Torrent) NumPieces() int { return len(t.Pieces) }

// PieceSize returns the length of piece i; the last piece may be short.
func (t *Torrent) PieceSize(i int) int64 {
	start := int64(i) * t.PieceLength
	return min(t.PieceLength, t.Length-start)
}

// Trackers returns every announce URL, tiers first, without duplicates.
func (t *Torrent) Trackers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, tier := range t.AnnounceList {
		for _, u := range tier {
			add(u)
		}
	}
	add(t.Announce)
	return out
}

// Parse parses a .torrent file.
func Parse(data []byte) (*Torrent, error) {
	v, err := bencode.Decode(data)
	if err != nil {
		return nil, err
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("top level is not a dictionary")
	}
	info, ok := root["info"].(map[string]any)
	if !ok {
		return nil, invalid("missing info dictionary")
	}
	raw, err := bencode.Raw(data, "info")
	if err != nil {
		return nil, err
	}

	t := &Torrent{InfoHash: sha1.Sum(raw), InfoBytes: append([]byte(nil), raw...)}
	t.Announce, _ = root["announce"].(string)
	if tiers, ok := root["announce-list"].([]any); ok {
		for _, tier := range tiers {
			list, ok := tier.([]any)
			if !ok {
				continue
			}
			var urls []string
			for _, u := range list {
				if s, ok := u.(string); ok {
					urls = append(urls, s)
				}
			}
			if len(urls) > 0 {
				t.AnnounceList = append(t.AnnounceList, urls)
			}
		}
	}
	if err := t.parseInfo(info); err != nil {
		return nil, err
	}
	return t, nil
}

// FromInfo builds a torrent from a bare info dictionary, as fetched from peers
// for a magnet link (BEP 9). trackers become its single announce tier.
func FromInfo(info []byte, trackers []string) (*Torrent, error) {
	meta := make([]byte, 0, len(info)+8)
	meta = append(meta, "d4:info"...)
	meta = append(meta, info...)
	meta = append(meta, 'e')
	t, err := Parse(meta)
	if err != nil {
		return nil, err
	}
	if len(trackers) > 0 {
		t.AnnounceList = [][]string{append([]string(nil), trackers...)}
	}
	return t, nil
}

func (t *Torrent) parseInfo(info map[string]any) error {
	name, ok := info["name"].(string)
	if !ok || !validComponent(name) {
		return invalid("bad name %q", name)
	}
	t.Name = name

	pl, ok := info["piece length"].(int64)
	if !ok || pl <= 0 || pl > MaxPieceLength {
		return invalid("bad piece length %d", pl)
	}
	t.PieceLength = pl

	pieces, ok := info["pieces"].(string)
	if !ok || len(pieces) == 0 || len(pieces)%HashSize != 0 {
		return invalid("pieces length %d is not a positive multiple of %d", len(pieces), HashSize)
	}
	t.Pieces = make([][HashSize]byte, len(pieces)/HashSize)
	for i := range t.Pieces {
		copy(t.Pieces[i][:], pieces[i*HashSize:])
	}

	if p, ok := info["private"].(int64); ok && p == 1 {
		t.Private = true
	}

	if length, ok := info["length"].(int64); ok {
		if _, multi := info["files"]; multi {
			return invalid("both length and files present")
		}
		if length < 0 {
			return invalid("negative length")
		}
		t.Files = []File{{Path: []string{name}, Length: length}}
	} else {
		files, ok := info["files"].([]any)
		if !ok || len(files) == 0 {
			return invalid("neither length nor files present")
		}
		t.MultiFile = true
		seen := map[string]bool{}
		for i, f := range files {
			file, err := parseFile(name, f)
			if err != nil {
				return fmt.Errorf("file %d: %w", i, err)
			}
			key := strings.Join(file.Path, "/")
			if seen[key] {
				return invalid("duplicate path %q", key)
			}
			seen[key] = true
			t.Files = append(t.Files, file)
		}
	}

	for i := range t.Files {
		if t.Files[i].Length > math.MaxInt64-t.Length {
			return invalid("total length overflows")
		}
		t.Files[i].Offset = t.Length
		t.Length += t.Files[i].Length
	}
	if t.Length == 0 {
		return invalid("torrent has no data")
	}
	if want := (t.Length + pl - 1) / pl; int64(len(t.Pieces)) != want {
		return invalid("%d piece hashes for %d pieces", len(t.Pieces), want)
	}
	return nil
}

func parseFile(name string, v any) (File, error) {
	d, ok := v.(map[string]any)
	if !ok {
		return File{}, invalid("not a dictionary")
	}
	length, ok := d["length"].(int64)
	if !ok || length < 0 {
		return File{}, invalid("bad length")
	}
	parts, ok := d["path"].([]any)
	if !ok || len(parts) == 0 {
		return File{}, invalid("missing path")
	}
	path := []string{name}
	for _, p := range parts {
		s, ok := p.(string)
		if !ok || !validComponent(s) {
			return File{}, invalid("unsafe path component %q", s)
		}
		path = append(path, s)
	}
	return File{Path: path, Length: length}, nil
}

// validComponent rejects path components that could escape the download
// directory or are unusable on common filesystems.
func validComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
