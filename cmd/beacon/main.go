// Command beacon is the Beacon desktop client.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
)

const usage = `beacon — peer-to-peer file sharing and chat

Usage:
  beacon <command> [arguments]

Commands:
  create    make a .torrent from a file or directory
  info      show what a .torrent contains
  get       download a .torrent or magnet link, seeding while it downloads
  seed      upload a complete torrent to other peers
  dht       run a DHT node only (a bootstrap node for private networks)
  chat      chat and share files with people on the local network
  tui       the same, in a full-screen terminal interface
  version   print the version

Run "beacon <command> -h" for a command's flags.
`

// version is set at release time with -ldflags "-X main.version=...".
var version = ""

// versionString reports the release version, or the module version for a
// binary built with "go install ...@v1.0.0", or "dev".
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

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
	case "dht":
		return cmdDHT(ctx, args[1:])
	case "chat":
		return cmdChat(ctx, args[1:])
	case "tui":
		return cmdTUI(ctx, args[1:])
	case "version", "-version", "--version":
		fmt.Println("beacon", versionString())
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprintf(os.Stderr, "beacon: unknown command %q\n\n%s", args[0], usage)
		return errUsage
	}
}
