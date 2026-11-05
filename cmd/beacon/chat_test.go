package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/mesh"
)

func TestLoadIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity")
	a, created, err := loadIdentity(path)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode %v", fi.Mode().Perm())
	}
	b, created, err := loadIdentity(path)
	if err != nil || created || b.Fingerprint() != a.Fingerprint() {
		t.Fatal("identity not reloaded")
	}
	os.WriteFile(path, []byte("short"), 0o600)
	if _, _, err := loadIdentity(path); err == nil {
		t.Fatal("corrupt identity accepted")
	}
}

func TestNoteShare(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &chat{ctx: ctx, events: make(chan event, 8)}
	c.noteShare("alice", "shared photos (1 MB) magnet:?xt=urn:btih:589bd9d481aeab6128ed08a399a7a8f1c380988e&dn=photos trailing")
	c.noteShare("mallory", "magnet:?xt=urn:btih:nothex")
	c.noteShare("bob", "no link here")
	if len(c.shares) != 1 || c.shares[0].Name != "photos" || c.shares[0].From != "alice" {
		t.Fatalf("shares %+v", c.shares)
	}
	select {
	case e := <-c.events:
		if e.Kind != "info" {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("no notice")
	}
}

func TestEventFormat(t *testing.T) {
	ts := time.Date(2026, 11, 3, 9, 5, 0, 0, time.Local)
	for _, tt := range []struct {
		e    event
		want string
	}{
		{event{Time: ts, Kind: "channel", Channel: "#general", From: "alice", Text: "hi"}, "09:05 [#general] alice: hi"},
		{event{Time: ts, Kind: "dm", From: "bob", Text: "psst"}, "09:05 [dm] bob: psst"},
		{event{Time: ts, Kind: "info", Text: "bob is nearby"}, "09:05 * bob is nearby"},
		{event{Time: ts, Kind: "error", Text: "oops"}, "09:05 ! oops"},
	} {
		if got := tt.e.format(); got != tt.want {
			t.Errorf("%q, want %q", got, tt.want)
		}
	}
}

func TestTagIfShared(t *testing.T) {
	alice := mesh.Fingerprint("aaaa1111")
	mallory := mesh.Fingerprint("bbbb2222")
	peers := []mesh.Peer{{Fingerprint: alice, Nickname: "alice"}}
	if got := tagIfShared(alice, "alice", peers); got != "alice" {
		t.Fatalf("unique nickname shown as %q", got)
	}
	peers = append(peers, mesh.Peer{Fingerprint: mallory, Nickname: "alice"})
	if a, m := tagIfShared(alice, "alice", peers), tagIfShared(mallory, "alice", peers); a != "alice#aaaa" || m != "alice#bbbb" {
		t.Fatalf("shared nickname shown as %q and %q", a, m)
	}
}
