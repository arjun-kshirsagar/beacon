package torrent

import (
	"crypto/sha1"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

// DefaultPieceLength is the piece length Create uses when given zero.
const DefaultPieceLength = 256 << 10

// Create builds a .torrent for the file or directory at path and returns the
// encoded metainfo. A directory becomes a multi-file torrent of the regular files
// under it, in lexical order. announce may be empty for trackerless use.
func Create(path string, pieceLength int64, announce string) ([]byte, error) {
	if pieceLength == 0 {
		pieceLength = DefaultPieceLength
	}
	if pieceLength < 0 || pieceLength > MaxPieceLength {
		return nil, fmt.Errorf("torrent: piece length %d out of range", pieceLength)
	}
	path = filepath.Clean(path)
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	type entry struct {
		abs  string
		rel  []string
		size int64
	}
	var entries []entry
	if st.Mode().IsRegular() {
		entries = append(entries, entry{abs: path, size: st.Size()})
	} else if st.IsDir() {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(path, p)
			if err != nil {
				return err
			}
			entries = append(entries, entry{abs: p, rel: splitPath(rel), size: info.Size()})
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("torrent: %s contains no files", path)
		}
	} else {
		return nil, fmt.Errorf("torrent: %s is not a file or directory", path)
	}

	// Hash pieces across file boundaries.
	var pieces []byte
	h := sha1.New()
	var filled int64
	buf := make([]byte, 32<<10)
	for _, e := range entries {
		f, err := os.Open(e.abs)
		if err != nil {
			return nil, err
		}
		for {
			n, err := f.Read(buf[:min(int64(len(buf)), pieceLength-filled)])
			h.Write(buf[:n])
			filled += int64(n)
			if filled == pieceLength {
				pieces = h.Sum(pieces)
				h.Reset()
				filled = 0
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, err
			}
		}
		f.Close()
	}
	if filled > 0 {
		pieces = h.Sum(pieces)
	}

	info := map[string]any{
		"name":         filepath.Base(path),
		"piece length": pieceLength,
		"pieces":       pieces,
	}
	if st.Mode().IsRegular() {
		info["length"] = st.Size()
	} else {
		files := make([]any, len(entries))
		for i, e := range entries {
			files[i] = map[string]any{"length": e.size, "path": e.rel}
		}
		info["files"] = files
	}
	meta := map[string]any{"info": info}
	if announce != "" {
		meta["announce"] = announce
	}
	return bencode.Encode(meta)
}

func splitPath(rel string) []string {
	return strings.Split(filepath.ToSlash(rel), "/")
}
