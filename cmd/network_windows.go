//go:build windows
// +build windows

package cmd

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsCapture struct {
	fd windows.Handle
}

func openCapture(iface string) (captureHandle, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("cannot open raw socket: %w (requires administrator)", err)
	}

	ip := resolveIfaceIP(iface)
	if ip == nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("cannot resolve IP for interface %s", iface)
	}

	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ip.To4())
	if err := windows.Bind(fd, sa); err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("cannot bind to %s: %w", iface, err)
	}

	// SIO_RCVALL to capture all packets
	var optVal uint32 = 1 // RCVALL_ON
	var bytesReturned uint32
	err = windows.WSAIoctl(fd, 0x98000001, (*byte)(unsafe.Pointer(&optVal)), 4, nil, 0, &bytesReturned, nil, 0)
	if err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("cannot enable promiscuous mode: %w", err)
	}

	tv := int32(1000) // 1 second
	windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, int(tv))

	return &windowsCapture{fd: fd}, nil
}

func resolveIfaceIP(name string) net.IP {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		// try as IP address directly
		if ip := net.ParseIP(name); ip != nil {
			return ip
		}
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP.To4()
		}
	}
	return nil
}

func (c *windowsCapture) Read(buf []byte) (int, error) {
	var flags uint32
	wsaBuf := windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
	var n uint32
	err := windows.WSARecv(c.fd, &wsaBuf, 1, &n, &flags, nil, nil)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == 10060 { // WSAETIMEDOUT
			return 0, nil
		}
		return 0, err
	}
	return int(n), nil
}

func (c *windowsCapture) Close() error {
	return windows.Closesocket(c.fd)
}

func (c *windowsCapture) HasEthernetHeader() bool {
	return false
}

