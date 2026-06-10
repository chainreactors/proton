//go:build linux
// +build linux

package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type linuxCapture struct {
	fd int
}

func openCapture(iface string) (captureHandle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("cannot open raw socket on %s: %w (requires root or CAP_NET_RAW)", iface, err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("cannot bind to %s: %w", iface, err)
	}

	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024)

	tv := unix.Timeval{Sec: 1}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	return &linuxCapture{fd: fd}, nil
}

func (c *linuxCapture) Read(buf []byte) (int, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if isTimeout(err) {
				return 0, nil
			}
			return 0, err
		}
		return n, nil
	}
}

func (c *linuxCapture) Close() error {
	return unix.Close(c.fd)
}

func (c *linuxCapture) HasEthernetHeader() bool {
	return true
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func isTimeout(err error) bool {
	if os.IsTimeout(err) {
		return true
	}
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
		return true
	}
	return false
}

// setReadDeadline sets the read timeout on the socket.
func (c *linuxCapture) setReadDeadline(d time.Duration) {
	tv := unix.Timeval{Sec: int64(d.Seconds())}
	if tv.Sec == 0 {
		tv.Usec = int64(d.Microseconds())
	}
	unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}
