//go:build unix

package transport

import (
	"net"
	"syscall"
)

// enableMulticastLoop undoes ListenMulticastUDP's IP_MULTICAST_LOOP=0, so
// processes on this host receive our announcements too.
func enableMulticastLoop(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
