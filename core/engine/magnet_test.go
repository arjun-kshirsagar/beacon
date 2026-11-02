package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/dht"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// TestMagnetOverDHT is the Phase 2 milestone in miniature: a magnet link with no
// trackers is resolved through the DHT, its metadata is fetched from a peer, and
// the files download and verify.
func TestMagnetOverDHT(t *testing.T) {
	mem := transport.NewMemory()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	startNode := func(addr string, boot []string) *dht.Node {
		n, err := dht.New(dht.Config{Transport: mem, Addr: addr, Bootstrap: boot, QueryTimeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			n.Run(ctx)
			close(done)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		return n
	}
	boot := []string{"10.0.0.1:6881"}
	startNode(boot[0], nil)
	for i := 1; i < 20; i++ {
		n := startNode(fmt.Sprintf("10.0.%d.1:6881", i), boot)
		if err := n.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// The seeder listens for peers on 10.0.100.1:7000 and announces that port.
	src := t.TempDir()
	tor := seedDir(t, src)
	serve(t, newClient(t, tor, src, mem), mem, "10.0.100.1:7000")
	seedNode := startNode("10.0.100.1:6881", boot)
	if err := seedNode.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := seedNode.Announce(ctx, tor.InfoHash, 7000); err != nil {
		t.Fatal(err)
	}

	// The leecher has only the magnet link.
	magnet, err := torrent.ParseMagnet(fmt.Sprintf("magnet:?xt=urn:btih:%x&dn=share", tor.InfoHash))
	if err != nil {
		t.Fatal(err)
	}
	leechNode := startNode("10.0.101.1:6881", boot)
	if err := leechNode.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	found, err := leechNode.GetPeers(ctx, magnet.InfoHash)
	if err != nil || len(found) == 0 {
		t.Fatalf("GetPeers: %v, %v", found, err)
	}
	peers := make(chan string, len(found))
	var addrs []string
	for _, p := range found {
		peers <- p.String()
		addrs = append(addrs, p.String())
	}
	close(peers)

	info, err := FetchMetadata(ctx, mem, magnet.InfoHash, peers, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := torrent.FromInfo(info, magnet.Trackers)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	c := newClient(t, got, dst, mem)
	if err := c.Download(ctx, addrs); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, src, dst)
}
