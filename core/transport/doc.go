// Package transport defines how core packages reach the network.
//
// Core code never opens sockets or radios directly. It dials and listens through a
// Transport, so the same engine runs over TCP on a desktop, over Wi-Fi Direct on
// Android, and over an in-memory network in tests.
package transport

import (
	"context"
	"net"
)

// Transport opens stream connections to peers and accepts them from peers.
type Transport interface {
	// Dial connects to addr. The address format is transport-specific.
	Dial(ctx context.Context, addr string) (net.Conn, error)
	// Listen accepts incoming connections on addr.
	Listen(addr string) (net.Listener, error)
}
