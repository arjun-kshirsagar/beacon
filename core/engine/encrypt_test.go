package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/peer"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

func newClientEnc(t *testing.T, tor *torrent.Torrent, dir string, tr transport.Transport, enc Encryption) *Client {
	t.Helper()
	store, err := OpenStorage(dir, tor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	c, err := New(tor, store, Config{Transport: tr, Encryption: enc})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tapTransport records everything written on connections it dials.
type tapTransport struct {
	*transport.Memory
	mu  sync.Mutex
	out bytes.Buffer
}

func (tt *tapTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := tt.Memory.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: c, tt: tt}, nil
}

func (tt *tapTransport) sawPlaintext() bool {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return bytes.Contains(tt.out.Bytes(), []byte(peer.Protocol))
}

type tapConn struct {
	net.Conn
	tt *tapTransport
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.tt.mu.Lock()
	c.tt.out.Write(p)
	c.tt.mu.Unlock()
	return c.Conn.Write(p)
}

func TestEncryptionPolicies(t *testing.T) {
	src := t.TempDir()
	tor := seedDir(t, src)
	tests := []struct {
		name          string
		seeder, leech Encryption
		ok, encrypted bool
	}{
		{"prefer both", EncryptPrefer, EncryptPrefer, true, true},
		{"require both", EncryptRequire, EncryptRequire, true, true},
		{"require leecher, prefer seeder", EncryptPrefer, EncryptRequire, true, true},
		{"prefer leecher falls back to plaintext", EncryptDisable, EncryptPrefer, true, false},
		{"off both", EncryptDisable, EncryptDisable, true, false},
		{"require leecher, plaintext seeder", EncryptDisable, EncryptRequire, false, false},
		{"plaintext leecher, require seeder", EncryptRequire, EncryptDisable, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := transport.NewMemory()
			seeder := newClientEnc(t, tor, src, mem, tt.seeder)
			serve(t, seeder, mem, "10.0.0.1:6881")
			dst := t.TempDir()
			wire := &tapTransport{Memory: mem}
			c := newClientEnc(t, tor, dst, wire, tt.leech)

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err := c.Download(ctx, []string{"10.0.0.1:6881"})
			if !tt.ok {
				if !errors.Is(err, ErrIncomplete) {
					t.Fatalf("got %v, want ErrIncomplete", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sameFiles(t, src, dst)
			if plain := wire.sawPlaintext(); plain == tt.encrypted {
				t.Fatalf("plaintext handshake on the wire = %v, want %v", plain, !tt.encrypted)
			}
		})
	}
}

func TestPreferFallsBackForLegacyPeer(t *testing.T) {
	// The staller speaks only plaintext and closes on MSE bytes; endgame still
	// needs its plaintext connection to be harmless, and the honest seeder must
	// finish the job.
	mem := transport.NewMemory()
	src := t.TempDir()
	tor := seedDir(t, src)
	staller(t, mem, "10.0.0.66:6881", tor)
	serve(t, newClient(t, tor, src, mem), mem, "10.0.0.1:6881")
	dst := t.TempDir()
	c := newClient(t, tor, dst, mem)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Download(ctx, []string{"10.0.0.66:6881", "10.0.0.1:6881"}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)
}
