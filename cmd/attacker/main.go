// Command attacker runs the attacks of Beacon's attack lab against nodes in
// the local Docker testbed (testbed/), to show each defense holding. It
// refuses to run anywhere else: see guard.go and docs/attacks.md.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
)

const usage = `attacker: attack-lab tools for the Beacon testbed only

Usage:
  attacker <attack> [flags]

Attacks (see docs/attacks.md):
  poison       seed a torrent with corrupted pieces
  flood        too many connections, each flooding control messages
  badmeta      answer magnet metadata requests with the wrong data
  sybil        many fake DHT nodes from one address (eclipse attempt)
  badtorrents  write malformed .torrent files
  meshflood    flood a mesh node with signed messages from random senders
  impersonate  pass for someone on the mesh

Runs only with BEACON_TESTBED=1 and only against loopback or private
addresses.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run() error {
	if err := requireTestbed(); err != nil {
		return err
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("attacker: no attack given")
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	args := os.Args[2:]
	switch os.Args[1] {
	case "poison":
		return cmdPoison(ctx, args)
	case "flood":
		return cmdFlood(ctx, args)
	case "badmeta":
		return cmdBadMeta(ctx, args)
	case "sybil":
		return cmdSybil(ctx, args)
	case "badtorrents":
		return cmdBadTorrents(args)
	case "meshflood":
		return cmdMeshFlood(ctx, args)
	case "impersonate":
		return cmdImpersonate(ctx, args)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("attacker: unknown attack %q", os.Args[1])
	}
}
