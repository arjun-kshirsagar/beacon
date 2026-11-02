package transport

import (
	"context"
	"fmt"
	"net"
)

// MulticastTransport joins multicast groups, for local peer discovery.
type MulticastTransport interface {
	// ListenMulticast joins group (ip:port). The returned socket receives the
	// group's datagrams, and WriteTo the group address sends to every member.
	ListenMulticast(group string) (net.PacketConn, error)
	// ResolveAddr turns a host:port string into an address WriteTo accepts.
	ResolveAddr(ctx context.Context, addr string) (net.Addr, error)
}

// ListenMulticast joins an IPv4 multicast group on the default interface.
// Multicast loopback is turned on where the platform allows it, so clients on
// the same machine can find each other.
func (UDP) ListenMulticast(group string) (net.PacketConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return nil, err
	}
	if !addr.IP.IsMulticast() {
		return nil, fmt.Errorf("transport: %s is not a multicast address", group)
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := enableMulticastLoop(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
