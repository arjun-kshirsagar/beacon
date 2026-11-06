package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

// The attack lab must never touch real networks: AGENTS.md allows these tools
// only against the local testbed. Two guards enforce it before any packet is
// sent:
//
//  1. BEACON_TESTBED=1 must be set. The testbed's containers set it; a
//     shell does not, so running a tool by accident does nothing.
//  2. Every target must resolve to a loopback or private (RFC 1918 / ULA)
//     address. Public addresses, and names that resolve to them, are refused.
//
// The tools also never contact trackers or DHT bootstrap routers on their own,
// and every flood is bounded.

var errNotTestbed = errors.New("attacker: refusing to run outside the testbed (set BEACON_TESTBED=1 inside it)")

func requireTestbed() error {
	if os.Getenv("BEACON_TESTBED") != "1" {
		return errNotTestbed
	}
	return nil
}

// labAddr reports whether addr may be targeted: loopback or private only.
func labAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate()
}

// target resolves host:port and refuses anything outside the lab ranges.
// Every address the name resolves to must be allowed, so a name cannot mix a
// lab address with a public one.
func target(hostport string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("attacker: resolving %s: %w", host, err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("attacker: %s has no address", host)
	}
	for _, ip := range ips {
		if !labAddr(ip) {
			return netip.AddrPort{}, fmt.Errorf("attacker: refusing %s: %v is not a loopback or private address", hostport, ip)
		}
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(p)), nil
}

// labListen refuses to listen on anything but a lab or unspecified address;
// inside the testbed's internal network that is still unreachable from
// outside.
func labListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("attacker: listen on an IP address, not %q", host)
	}
	if !ip.IsUnspecified() && !labAddr(ip) {
		return fmt.Errorf("attacker: refusing to listen on %v", ip)
	}
	return nil
}
