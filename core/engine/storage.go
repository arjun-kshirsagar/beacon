package engine

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
)

// Storage maps a torrent's contiguous byte range onto its files under a
// directory. Files are opened through an os.Root, so no path in the torrent can
// reach outside that directory.
type Storage struct {
	files []torrent.File
	fds   []*os.File
}

// OpenStorage opens, creating where needed, the files of t under dir. Existing
// files are kept so downloads can resume and complete files can be seeded.
func OpenStorage(dir string, t *torrent.Torrent) (*Storage, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	s := &Storage{files: t.Files}
	for _, f := range t.Files {
		name := filepath.Join(f.Path...)
		if d := filepath.Dir(name); d != "." {
			if err := root.MkdirAll(d, 0o755); err != nil {
				s.Close()
				return nil, err
			}
		}
		fd, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.fds = append(s.fds, fd)
		st, err := fd.Stat()
		if err != nil {
			s.Close()
			return nil, err
		}
		switch {
		case st.Size() > f.Length:
			s.Close()
			return nil, fmt.Errorf("engine: %s is %d bytes, torrent says %d", name, st.Size(), f.Length)
		case st.Size() < f.Length:
			if err := fd.Truncate(f.Length); err != nil {
				s.Close()
				return nil, err
			}
		}
	}
	return s, nil
}

// ReadAt reads len(p) bytes at torrent offset off.
func (s *Storage) ReadAt(p []byte, off int64) (int, error) {
	return s.io(p, off, (*os.File).ReadAt)
}

// WriteAt writes p at torrent offset off.
func (s *Storage) WriteAt(p []byte, off int64) (int, error) {
	return s.io(p, off, (*os.File).WriteAt)
}

func (s *Storage) io(p []byte, off int64, op func(*os.File, []byte, int64) (int, error)) (int, error) {
	done := 0
	for i, f := range s.files {
		if done == len(p) {
			break
		}
		pos := off + int64(done)
		if pos >= f.Offset+f.Length || f.Length == 0 {
			continue
		}
		if pos < f.Offset {
			break
		}
		chunk := min(int64(len(p)-done), f.Offset+f.Length-pos)
		n, err := op(s.fds[i], p[done:done+int(chunk)], pos-f.Offset)
		done += n
		if err != nil && !(errors.Is(err, io.EOF) && int64(n) == chunk) {
			return done, err
		}
	}
	if done < len(p) {
		return done, io.ErrUnexpectedEOF
	}
	return done, nil
}

// Close closes every file.
func (s *Storage) Close() error {
	var errs []error
	for _, fd := range s.fds {
		errs = append(errs, fd.Close())
	}
	return errors.Join(errs...)
}

// Verify hashes every piece in storage and returns those that match t.
func Verify(t *torrent.Torrent, s *Storage) (peer.Bitfield, error) {
	have := peer.NewBitfield(t.NumPieces())
	buf := make([]byte, t.PieceLength)
	for i := range t.NumPieces() {
		p := buf[:t.PieceSize(i)]
		if _, err := s.ReadAt(p, int64(i)*t.PieceLength); err != nil {
			return nil, fmt.Errorf("engine: reading piece %d: %w", i, err)
		}
		if sha1.Sum(p) == t.Pieces[i] {
			have.Set(i)
		}
	}
	return have, nil
}
