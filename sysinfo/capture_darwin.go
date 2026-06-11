//go:build darwin
// +build darwin

package sysinfo

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinCapture struct {
	file   *os.File
	bufLen int
}

// OpenCapture opens a BPF packet capture on the given network interface (Darwin/macOS).
func OpenCapture(iface string) (CaptureHandle, error) {
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err = unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot open BPF device: %w (requires root)", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}

	// BIOCSETIF
	var ifReq [32]byte
	copy(ifReq[:], []byte(ifi.Name))
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(0x8020426C), // BIOCSETIF
		uintptr(unsafe.Pointer(&ifReq[0]))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("BIOCSETIF %s: %v", iface, errno)
	}

	// BIOCIMMEDIATE
	imm := 1
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(0x80044270), // BIOCIMMEDIATE
		uintptr(unsafe.Pointer(&imm))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("BIOCIMMEDIATE: %v", errno)
	}

	// BIOCGBLEN - get buffer length
	var bufLen int
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(0x40044266), // BIOCGBLEN
		uintptr(unsafe.Pointer(&bufLen))); errno != 0 {
		bufLen = 4096
	}

	// read timeout
	tv := unix.Timeval{Sec: 1}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	f := os.NewFile(uintptr(fd), "bpf")
	return &darwinCapture{file: f, bufLen: bufLen}, nil
}

func (c *darwinCapture) Read(buf []byte) (int, error) {
	n, err := c.file.Read(buf)
	if err != nil {
		if os.IsTimeout(err) {
			return 0, nil
		}
		return 0, err
	}
	if n < 18 {
		return 0, nil
	}
	// BPF header: 4 bytes timestamp_sec, 4 bytes timestamp_usec,
	// 4 bytes capture length, 4 bytes original length, 2 bytes header length
	hdrLen := int(binary.LittleEndian.Uint16(buf[16:18]))
	if hdrLen >= n {
		return 0, nil
	}
	// shift payload to start of buf
	payloadLen := n - hdrLen
	copy(buf, buf[hdrLen:n])
	return payloadLen, nil
}

func (c *darwinCapture) Close() error {
	return c.file.Close()
}

func (c *darwinCapture) HasEthernetHeader() bool {
	return true
}
