//go:build windows

package sysinfo

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll                      = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
	modiphlpapi                   = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable       = modiphlpapi.NewProc("GetExtendedTcpTable")
)

func ReadProcessEnv(pid int) ([]byte, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	pbi, err := queryProcessBasicInfo(h)
	if err != nil {
		return nil, err
	}

	var peb [6]uintptr
	err = readProcMem(h, pbi.PebBaseAddress, unsafe.Pointer(&peb[0]), unsafe.Sizeof(peb))
	if err != nil {
		return nil, fmt.Errorf("read PEB: %w", err)
	}
	paramsAddr := peb[4] // RTL_USER_PROCESS_PARAMETERS at PEB+0x20

	var envAddr uintptr
	err = readProcMem(h, paramsAddr+0x80, unsafe.Pointer(&envAddr), unsafe.Sizeof(envAddr))
	if err != nil {
		return nil, fmt.Errorf("read env addr: %w", err)
	}
	if envAddr == 0 {
		return nil, fmt.Errorf("empty env addr")
	}

	buf, err := readUTF16Block(h, envAddr, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read env block: %w", err)
	}

	return decodeEnvBlock(buf), nil
}

func ReadProcessCmdline(pid int) ([]byte, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	pbi, err := queryProcessBasicInfo(h)
	if err != nil {
		return nil, err
	}

	var peb [6]uintptr
	err = readProcMem(h, pbi.PebBaseAddress, unsafe.Pointer(&peb[0]), unsafe.Sizeof(peb))
	if err != nil {
		return nil, err
	}
	paramsAddr := peb[4]

	var strLen uint16
	var strAddr uintptr
	if err := readProcMem(h, paramsAddr+0x70, unsafe.Pointer(&strLen), 2); err != nil {
		return nil, fmt.Errorf("read cmdline len: %w", err)
	}
	if err := readProcMem(h, paramsAddr+0x70+8, unsafe.Pointer(&strAddr), unsafe.Sizeof(strAddr)); err != nil {
		return nil, fmt.Errorf("read cmdline addr: %w", err)
	}

	if strLen == 0 || strLen > 32768 {
		return nil, nil
	}
	if strAddr == 0 {
		return nil, fmt.Errorf("empty cmdline addr")
	}
	buf := make([]byte, strLen)
	if err := readProcMem(h, strAddr, unsafe.Pointer(&buf[0]), uintptr(strLen)); err != nil {
		return nil, fmt.Errorf("read cmdline: %w", err)
	}

	return utf16BytesToUTF8(buf), nil
}

func ReadProcessFDs(pid int) ([]byte, error) {
	return nil, nil
}

func ReadProcessConns(pid int) ([]byte, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, windows.AF_INET, 5, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
		1, windows.AF_INET, 5, 0)
	if ret != 0 {
		return nil, nil
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	var lines []string
	entrySize := 24
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + int(i)*entrySize
		if offset+entrySize > len(buf) {
			break
		}
		state := *(*uint32)(unsafe.Pointer(&buf[offset]))
		localAddr := net.IP(buf[offset+4 : offset+8])
		localPort := uint16(buf[offset+8])<<8 | uint16(buf[offset+9])
		remoteAddr := net.IP(buf[offset+12 : offset+16])
		remotePort := uint16(buf[offset+16])<<8 | uint16(buf[offset+17])
		ownerPid := *(*uint32)(unsafe.Pointer(&buf[offset+20]))

		if int(ownerPid) != pid {
			continue
		}
		if state < 2 {
			continue
		}
		lines = append(lines, fmt.Sprintf("tcp local=%s:%d remote=%s:%d",
			localAddr, localPort, remoteAddr, remotePort))
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func ReadProcessPipes(pid int) ([]byte, error) {
	pattern := `\\.\pipe\*`
	var fd windows.Win32finddata
	h, err := windows.FindFirstFile(syscall.StringToUTF16Ptr(pattern), &fd)
	if err != nil {
		return nil, nil
	}
	defer windows.FindClose(h)

	var lines []string
	for {
		name := syscall.UTF16ToString(fd.FileName[:])
		lines = append(lines, `\\.\pipe\`+name)
		if err := windows.FindNextFile(h, &fd); err != nil {
			break
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

func queryProcessBasicInfo(h windows.Handle) (*processBasicInfo, error) {
	var pbi processBasicInfo
	var retLen uint32
	ret, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h), 0,
		uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)))
	if ret != 0 {
		return nil, fmt.Errorf("NtQueryInformationProcess: %x", ret)
	}
	return &pbi, nil
}

func readProcMem(h windows.Handle, addr uintptr, buf unsafe.Pointer, size uintptr) error {
	var nRead uintptr
	return windows.ReadProcessMemory(h, addr, (*byte)(buf), size, &nRead)
}

func readProcMemBytes(h windows.Handle, addr uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	var nRead uintptr
	err := windows.ReadProcessMemory(h, addr, &buf[0], uintptr(size), &nRead)
	if nRead > 0 {
		return buf[:nRead], err
	}
	if err != nil {
		return nil, err
	}
	return buf[:0], nil
}

func readUTF16Block(h windows.Handle, addr uintptr, max int) ([]byte, error) {
	const chunkSize = 4096
	var buf []byte
	for len(buf) < max {
		n := chunkSize
		if remaining := max - len(buf); remaining < n {
			n = remaining
		}
		chunk, err := readProcMemBytes(h, addr+uintptr(len(buf)), n)
		if len(chunk) > 0 {
			buf = append(buf, chunk...)
			if end, ok := utf16DoubleNulEnd(buf); ok {
				return buf[:end], nil
			}
		}
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, fmt.Errorf("short read at %#x", addr+uintptr(len(buf)))
		}
	}
	return nil, fmt.Errorf("utf16 block exceeds %d bytes without terminator", max)
}

func utf16DoubleNulEnd(b []byte) (int, bool) {
	for i := 0; i+3 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 0 && b[i+3] == 0 {
			return i + 4, true
		}
	}
	return 0, false
}

func decodeEnvBlock(b []byte) []byte {
	var result []byte
	for i := 0; i+1 < len(b); i += 2 {
		ch := uint16(b[i]) | uint16(b[i+1])<<8
		if ch == 0 {
			if len(result) > 0 && result[len(result)-1] != '\n' {
				result = append(result, '\n')
			}
			if i+3 < len(b) && b[i+2] == 0 && b[i+3] == 0 {
				break
			}
			continue
		}
		if ch < 128 {
			result = append(result, byte(ch))
		}
	}
	return result
}

func utf16BytesToUTF8(b []byte) []byte {
	var result []byte
	for i := 0; i+1 < len(b); i += 2 {
		ch := uint16(b[i]) | uint16(b[i+1])<<8
		if ch == 0 {
			break
		}
		if ch < 128 {
			result = append(result, byte(ch))
		}
	}
	return result
}
