package transport

import (
	"context"
	"net"
)

// TCP is a Transport over the operating system's TCP stack.
type TCP struct {
	Dialer net.Dialer
}

// Dial connects to a host:port address.
func (t *TCP) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.Dialer.DialContext(ctx, "tcp", addr)
}

// Listen listens on a host:port address.
func (t *TCP) Listen(addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", addr)
}
