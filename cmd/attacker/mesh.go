package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/lan"
	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const maxMeshPackets = 5000

// meshLink opens a LAN mesh link to a node in the lab.
func meshLink(ctx context.Context, to string) (transport.Link, error) {
	addr, err := target(to)
	if err != nil {
		return nil, err
	}
	links, err := lan.Listen(lan.Config{Stream: &transport.TCP{}, Listen: "127.0.0.1:0"})
	if err != nil {
		return nil, err
	}
	if err := links.Dial(ctx, addr.String()); err != nil {
		return nil, err
	}
	return links.Accept(ctx)
}

// attackerID is a throwaway identity: keys made for this run only.
type attackerID struct {
	sign  ed25519.PrivateKey
	noise [32]byte
}

func newAttackerID() attackerID {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var a attackerID
	a.sign = priv
	rand.Read(a.noise[:])
	return a
}

func randID() (id [mesh.IDSize]byte) {
	rand.Read(id[:])
	return id
}

// packet builds a fresh packet from sender.
func packet(typ mesh.Type, sender mesh.PeerID, payload []byte) *mesh.Packet {
	return &mesh.Packet{Type: typ, TTL: mesh.MaxTTL, ID: mesh.PacketID(randID()),
		Time: time.Now().Truncate(time.Millisecond), Sender: sender, Payload: payload}
}

// announce builds an announce payload (docs/protocol-spec.md, "Announce").
func (a attackerID) announce(nick string) []byte {
	b := append([]byte(nil), a.sign.Public().(ed25519.PublicKey)...)
	b = append(b, a.noise[:]...)
	b = append(b, byte(len(nick)))
	return append(b, nick...)
}

func channelPayload(channel, text string) []byte {
	return append(append([]byte{byte(len(channel))}, channel...), text...)
}

// send writes one packet as a single LAN frame (MTU 8192 fits any packet).
func send(l transport.Link, p *mesh.Packet) error {
	return l.WriteFrame(append([]byte{0x03}, p.Encode()...))
}

// cmdMeshFlood floods a node with validly signed channel messages, each from
// a new random sender ID so per-sender limits never see the same one twice.
// The defense: a per-link packet rate limit (50 a second after a burst of
// 512), so the flood is cut at the first hop and relays keep carrying honest
// traffic.
func cmdMeshFlood(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("meshflood", flag.ContinueOnError)
	to := fs.String("target", "", "victim's LAN link host:port")
	count := fs.Int("count", 3000, fmt.Sprintf("packets to send (at most %d)", maxMeshPackets))
	if err := fs.Parse(args); err != nil || *to == "" {
		return errors.New("usage: attacker meshflood -target host:port [-count n]")
	}
	l, err := meshLink(ctx, *to)
	if err != nil {
		return err
	}
	defer l.Close()
	go func() { // drain what the victim sends
		for {
			if _, err := l.ReadFrame(); err != nil {
				return
			}
		}
	}()
	me := newAttackerID()
	n, sent := min(*count, maxMeshPackets), 0
	start := time.Now()
	for i := range n {
		p := packet(mesh.TypeChannel, randID(), channelPayload("#general", fmt.Sprint("flood ", i)))
		p.Sign(me.sign)
		if send(l, p) != nil {
			break
		}
		sent++
	}
	slog.Info("mesh flood done", "sent", sent, "in", time.Since(start).Round(time.Millisecond))
	time.Sleep(2 * time.Second) // let the victim drain before the link closes
	return nil
}

// cmdImpersonate listens on a mesh link for a channel message from -as, then
// tries to pass for that person four ways:
//
//  1. announces its own keys under the same nickname,
//  2. re-sends the captured message with the text changed (and a new packet
//     ID, so it is not a duplicate) under the original signature,
//  3. replays the captured message unchanged,
//  4. announces its own keys under the victim's sender ID.
//
// The defenses: identity is the fingerprint, not the nickname, so (1) shows
// up as a different person; signatures cover everything but the TTL, so (2)
// fails verification and is dropped; duplicates are filtered, so (3) does
// nothing; and a live sender ID stays bound to its first key, so (4) is
// ignored.
func cmdImpersonate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("impersonate", flag.ContinueOnError)
	to := fs.String("target", "", "a node's LAN link host:port")
	as := fs.String("as", "", "nickname of the person to impersonate")
	wait := fs.Duration("wait", 2*time.Minute, "how long to wait for a message from them")
	if err := fs.Parse(args); err != nil || *to == "" || *as == "" {
		return errors.New("usage: attacker impersonate -target host:port -as nickname [-wait d]")
	}
	l, err := meshLink(ctx, *to)
	if err != nil {
		return err
	}
	defer l.Close()

	// Watch traffic for the person's announce and then a channel message.
	frames := make(chan []byte, 64)
	go func() {
		defer close(frames)
		for {
			f, err := l.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	var theirID *mesh.PeerID
	var captured *mesh.Packet
	deadline := time.After(*wait)
	for captured == nil {
		select {
		case f, ok := <-frames:
			if !ok {
				return errors.New("attacker: link closed")
			}
			if len(f) < 2 || f[0] != 0x03 {
				continue
			}
			p, err := mesh.ParsePacket(f[1:])
			if err != nil {
				continue
			}
			switch {
			case p.Type == mesh.TypeAnnounce && len(p.Payload) > 65 && string(p.Payload[65:]) == *as:
				id := p.Sender
				theirID = &id
			case p.Type == mesh.TypeChannel && theirID != nil && p.Sender == *theirID:
				captured = p
			}
		case <-deadline:
			return fmt.Errorf("attacker: no channel message from %q within %v", *as, *wait)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	slog.Info("captured a message", "from", *as, "sender id", fmt.Sprintf("%x", captured.Sender))

	me := newAttackerID()
	myID := mesh.PeerID(randID())

	// 1. Same nickname, own keys.
	ann := packet(mesh.TypeAnnounce, myID, me.announce(*as))
	ann.Sign(me.sign)
	send(l, ann)
	time.Sleep(time.Second)
	own := packet(mesh.TypeChannel, myID, channelPayload("#general", "this is "+*as+", trust me"))
	own.Sign(me.sign)
	send(l, own)
	slog.Info("1. announced as a second " + *as + " with other keys")

	// 2. Their message with new text, their signature.
	forged := *captured
	forged.ID, forged.TTL = mesh.PacketID(randID()), mesh.MaxTTL
	ch := int(captured.Payload[0])
	forged.Payload = channelPayload(string(captured.Payload[1:1+ch]), "FORGED: send your keys to the attacker")
	send(l, &forged)
	slog.Info("2. sent their message with the text changed")

	// 3. Their message, unchanged.
	send(l, captured)
	slog.Info("3. replayed their message")

	// 4. Our keys under their sender ID.
	hijack := packet(mesh.TypeAnnounce, *theirID, me.announce(*as))
	hijack.Sign(me.sign)
	send(l, hijack)
	time.Sleep(time.Second)
	after := packet(mesh.TypeChannel, *theirID, channelPayload("#general", "HIJACKED: this came from their ID"))
	after.Sign(me.sign)
	send(l, after)
	slog.Info("4. claimed their sender ID")

	time.Sleep(2 * time.Second)
	slog.Info("impersonation attempts done")
	return nil
}
