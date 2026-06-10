//go:build windows
// +build windows

package cmd

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll                         = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess    = modntdll.NewProc("NtQueryInformationProcess")
	modiphlpapi                      = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable          = modiphlpapi.NewProc("GetExtendedTcpTable")
)

func readProcessEnv(pid int) ([]byte, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	pbi, err := queryProcessBasicInfo(h)
	if err != nil {
		return nil, err
	}

	// Read PEB
	var peb [6]uintptr // only need ProcessParameters at offset 0x20 (64-bit)
	err = readProcMem(h, pbi.PebBaseAddress, unsafe.Pointer(&peb[0]), unsafe.Sizeof(peb))
	if err != nil {
		return nil, fmt.Errorf("read PEB: %w", err)
	}
	paramsAddr := peb[4] // RTL_USER_PROCESS_PARAMETERS at PEB+0x20

	// Read UNICODE_STRING for Environment at offset 0x80
	var envAddr uintptr
	var envSize uint32
	err = readProcMem(h, paramsAddr+0x80, unsafe.Pointer(&envAddr), unsafe.Sizeof(envAddr))
	if err != nil {
		return nil, fmt.Errorf("read env addr: %w", err)
	}
	err = readProcMem(h, paramsAddr+0x80-8, unsafe.Pointer(&envSize), unsafe.Sizeof(envSize))
	if err != nil {
		return nil, fmt.Errorf("read env size: %w", err)
	}
	if envSize == 0 || envSize > 1<<20 {
		return nil, fmt.Errorf("invalid env size: %d", envSize)
	}

	buf := make([]byte, envSize)
	err = readProcMem(h, envAddr, unsafe.Pointer(&buf[0]), uintptr(envSize))
	if err != nil {
		return nil, fmt.Errorf("read env block: %w", err)
	}

	// UTF-16 null-separated → UTF-8 newline-separated
	return decodeEnvBlock(buf), nil
}

func readProcessCmdline(pid int) ([]byte, error) {
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

	// UNICODE_STRING CommandLine at offset 0x70
	var strLen uint16
	var strAddr uintptr
	readProcMem(h, paramsAddr+0x70, unsafe.Pointer(&strLen), 2)
	readProcMem(h, paramsAddr+0x70+8, unsafe.Pointer(&strAddr), unsafe.Sizeof(strAddr))

	if strLen == 0 || strLen > 32768 {
		return nil, nil
	}
	buf := make([]byte, strLen)
	readProcMem(h, strAddr, unsafe.Pointer(&buf[0]), uintptr(strLen))

	return utf16BytesToUTF8(buf), nil
}

func readProcessFDs(pid int) ([]byte, error) {
	// Windows doesn't expose file handles easily without NtQuerySystemInformation
	return nil, nil
}

func readProcessConns(pid int) ([]byte, error) {
	// GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, windows.AF_INET, 5, 0) // 5 = TCP_TABLE_OWNER_PID_ALL
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
	entrySize := 24 // sizeof(MIB_TCPROW_OWNER_PID)
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
		if state < 2 { // skip CLOSED
			continue
		}
		lines = append(lines, fmt.Sprintf("tcp local=%s:%d remote=%s:%d",
			localAddr, localPort, remoteAddr, remotePort))
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func readProcessPipes(pid int) ([]byte, error) {
	// Enumerate \\.\pipe\* - this lists all pipes on the system, not per-process
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

func decodeEnvBlock(b []byte) []byte {
	// UTF-16LE double-null terminated block → UTF-8 newline-separated
	var result []byte
	for i := 0; i+1 < len(b); i += 2 {
		ch := uint16(b[i]) | uint16(b[i+1])<<8
		if ch == 0 {
			if len(result) > 0 && result[len(result)-1] != '\n' {
				result = append(result, '\n')
			}
			if i+3 < len(b) && b[i+2] == 0 && b[i+3] == 0 {
				break // double null = end
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
