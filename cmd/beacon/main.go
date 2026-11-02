// Command beacon is the Beacon desktop client.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
)

const usage = `beacon — peer-to-peer file sharing and chat

Usage:
  beacon <command> [arguments]

Commands:
  create    make a .torrent from a file or directory
  info      show what a .torrent contains
  get       download a .torrent or magnet link, seeding while it downloads
  seed      upload a complete torrent to other peers
  version   print the version

Run "beacon <command> -h" for a command's flags.
`

var version = "dev"

// errUsage means the arguments were wrong; the usage text has been printed.
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, "beacon:", err)
		}
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errUsage
	}
	switch args[0] {
	case "create":
		return cmdCreate(args[1:])
	case "info":
		return cmdInfo(args[1:])
	case "get":
		return cmdGet(ctx, args[1:])
	case "seed":
		return cmdSeed(ctx, args[1:])
	case "version":
		fmt.Println("beacon", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprintf(os.Stderr, "beacon: unknown command %q\n\n%s", args[0], usage)
		return errUsage
	}
}
