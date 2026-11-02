//go:build !unix

package transport

import "net"

// enableMulticastLoop is a no-op where we do not set socket options directly;
// same-host clients will not see each other's announcements there.
func enableMulticastLoop(*net.UDPConn) error { return nil }
