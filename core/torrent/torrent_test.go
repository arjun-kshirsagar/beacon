package torrent

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

func encode(t testing.TB, v any) []byte {
	t.Helper()
	b, err := bencode.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSingleFile(t *testing.T) {
	pieces := strings.Repeat("a", 20) + strings.Repeat("b", 20)
	info := map[string]any{"name": "file.bin", "piece length": 4, "pieces": pieces, "length": 7}
	data := encode(t, map[string]any{
		"announce":      "http://t.example/announce",
		"announce-list": []any{[]any{"http://a.example/announce"}, []any{"http://t.example/announce"}},
		"info":          info,
	})
	tor, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha1.Sum(encode(t, info)); tor.InfoHash != want {
		t.Errorf("info-hash mismatch")
	}
	if tor.Name != "file.bin" || tor.Length != 7 || tor.NumPieces() != 2 || tor.MultiFile {
		t.Errorf("unexpected torrent %+v", tor)
	}
	if tor.PieceSize(0) != 4 || tor.PieceSize(1) != 3 {
		t.Errorf("piece sizes %d, %d", tor.PieceSize(0), tor.PieceSize(1))
	}
	if !reflect.DeepEqual(tor.Files, []File{{Path: []string{"file.bin"}, Length: 7}}) {
		t.Errorf("files = %+v", tor.Files)
	}
	want := []string{"http://a.example/announce", "http://t.example/announce"}
	if got := tor.Trackers(); !reflect.DeepEqual(got, want) {
		t.Errorf("Trackers() = %v, want %v", got, want)
	}
}

func TestParseMultiFile(t *testing.T) {
	data := encode(t, map[string]any{"info": map[string]any{
		"name": "dir", "piece length": 16, "pieces": strings.Repeat("x", 20),
		"files": []any{
			map[string]any{"length": 3, "path": []string{"a.txt"}},
			map[string]any{"length": 5, "path": []string{"sub", "b.txt"}},
		},
	}})
	tor, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []File{
		{Path: []string{"dir", "a.txt"}, Length: 3, Offset: 0},
		{Path: []string{"dir", "sub", "b.txt"}, Length: 5, Offset: 3},
	}
	if !tor.MultiFile || tor.Length != 8 || !reflect.DeepEqual(tor.Files, want) {
		t.Errorf("unexpected torrent %+v", tor)
	}
}

func TestParseInvalid(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "f", "piece length": 4, "pieces": strings.Repeat("a", 20), "length": 4}
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"zero piece length", func(m map[string]any) { m["piece length"] = 0 }},
		{"huge piece length", func(m map[string]any) { m["piece length"] = MaxPieceLength + 1 }},
		{"short pieces", func(m map[string]any) { m["pieces"] = "abc" }},
		{"piece count mismatch", func(m map[string]any) { m["length"] = 9 }},
		{"empty", func(m map[string]any) { m["length"] = 0 }},
		{"negative length", func(m map[string]any) { m["length"] = -1 }},
		{"dot-dot name", func(m map[string]any) { m["name"] = ".." }},
		{"slash name", func(m map[string]any) { m["name"] = "a/b" }},
		{"no length or files", func(m map[string]any) { delete(m, "length") }},
		{"traversal in path", func(m map[string]any) {
			delete(m, "length")
			m["files"] = []any{map[string]any{"length": 4, "path": []string{"..", "etc"}}}
		}},
		{"duplicate path", func(m map[string]any) {
			delete(m, "length")
			m["files"] = []any{
				map[string]any{"length": 2, "path": []string{"a"}},
				map[string]any{"length": 2, "path": []string{"a"}},
			}
		}},
	}
	for _, tt := range tests {
		info := base()
		tt.mutate(info)
		if _, err := Parse(encode(t, map[string]any{"info": info})); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", tt.name, err)
		}
	}
	if _, err := Parse([]byte("le")); !errors.Is(err, ErrInvalid) {
		t.Errorf("list: got %v", err)
	}
}

func TestCreateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "share")
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	a := bytes.Repeat([]byte("A"), 10)
	b := bytes.Repeat([]byte("B"), 25)
	os.WriteFile(filepath.Join(root, "a.txt"), a, 0o644)
	os.WriteFile(filepath.Join(root, "sub", "b.txt"), b, 0o644)

	meta, err := Create(root, 16, "http://t.example/announce")
	if err != nil {
		t.Fatal(err)
	}
	tor, err := Parse(meta)
	if err != nil {
		t.Fatal(err)
	}
	if tor.Name != "share" || tor.Length != 35 || tor.NumPieces() != 3 || tor.Announce != "http://t.example/announce" {
		t.Fatalf("unexpected torrent %+v", tor)
	}
	all := append(append([]byte{}, a...), b...)
	for i := range tor.NumPieces() {
		start := int64(i) * tor.PieceLength
		if sha1.Sum(all[start:start+tor.PieceSize(i)]) != tor.Pieces[i] {
			t.Errorf("piece %d hash mismatch", i)
		}
	}
	if !reflect.DeepEqual(tor.Files[1].Path, []string{"share", "sub", "b.txt"}) {
		t.Errorf("file path %v", tor.Files[1].Path)
	}

	single := filepath.Join(dir, "one.bin")
	os.WriteFile(single, a, 0o644)
	meta, err = Create(single, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if tor, err = Parse(meta); err != nil || tor.MultiFile || tor.Length != 10 {
		t.Fatalf("single file: %+v, %v", tor, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(encode(f, map[string]any{"announce": "http://t/a", "info": map[string]any{
		"name": "f", "piece length": 4, "pieces": strings.Repeat("a", 20), "length": 4}}))
	f.Add(encode(f, map[string]any{"info": map[string]any{
		"name": "d", "piece length": 16, "pieces": strings.Repeat("x", 20),
		"files": []any{map[string]any{"length": 3, "path": []string{"a"}}}}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		tor, err := Parse(data)
		if err != nil {
			return
		}
		if tor.Length <= 0 || tor.PieceLength <= 0 || tor.NumPieces() == 0 {
			t.Fatalf("accepted torrent with bad sizes: %+v", tor)
		}
		for _, file := range tor.Files {
			for _, c := range file.Path {
				if !validComponent(c) {
					t.Fatalf("accepted unsafe path %q", file.Path)
				}
			}
		}
	})
}
