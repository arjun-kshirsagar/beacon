package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// PacketTransport sends and receives datagrams. UDP trackers and the DHT use it.
type PacketTransport interface {
	// ListenPacket opens a datagram socket on addr; an empty addr picks one.
	ListenPacket(addr string) (net.PacketConn, error)
	// ResolveAddr turns a host:port string into an address WriteTo accepts.
	ResolveAddr(ctx context.Context, addr string) (net.Addr, error)
}

// UDP is a PacketTransport over the operating system's UDP stack.
type UDP struct{}

// ListenPacket listens on a host:port address.
func (UDP) ListenPacket(addr string) (net.PacketConn, error) {
	if addr == "" {
		addr = ":0"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", addr)
}

// ResolveAddr resolves host:port, preferring IPv4.
func (UDP) ResolveAddr(ctx context.Context, addr string) (net.Addr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("transport: no addresses for %s", host)
	}
	ip := ips[0]
	for _, a := range ips {
		if a.Unmap().Is4() {
			ip = a.Unmap()
			break
		}
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(ap), nil
}
