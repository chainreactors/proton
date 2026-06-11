//go:build windows

package sysinfo

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processVMRead           = 0x0010
	processQueryInformation = 0x0400
)

var (
	modpsapi              = syscall.NewLazyDLL("psapi.dll")
	procGetMappedFileName = modpsapi.NewProc("GetMappedFileNameW")
)

type windowsMemReader struct {
	handle windows.Handle
	pid    int
}

func NewMemoryReader(pid int) (MemoryReader, error) {
	h, err := windows.OpenProcess(processVMRead|processQueryInformation, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	return &windowsMemReader{handle: h, pid: pid}, nil
}

func (r *windowsMemReader) Regions() ([]MemoryRegion, error) {
	var regions []MemoryRegion
	var addr uintptr

	for {
		var mbi windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(r.handle, addr, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT && isReadableProtect(mbi.Protect) {
			mapped := getMappedFileName(r.handle, mbi.BaseAddress)
			regions = append(regions, MemoryRegion{
				BaseAddr:   uint64(mbi.BaseAddress),
				Size:       uint64(mbi.RegionSize),
				Perms:      protectToPerms(mbi.Protect),
				MappedFile: mapped,
			})
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return regions, nil
}

func getMappedFileName(handle windows.Handle, addr uintptr) string {
	var buf [260]uint16
	r, _, _ := procGetMappedFileName.Call(
		uintptr(handle), addr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:r])
}

func isReadableProtect(protect uint32) bool {
	switch protect {
	case windows.PAGE_READONLY,
		windows.PAGE_READWRITE,
		windows.PAGE_WRITECOPY,
		windows.PAGE_EXECUTE_READ,
		windows.PAGE_EXECUTE_READWRITE,
		windows.PAGE_EXECUTE_WRITECOPY:
		return true
	}
	return false
}

func protectToPerms(protect uint32) string {
	switch protect {
	case windows.PAGE_READONLY:
		return "r--"
	case windows.PAGE_READWRITE, windows.PAGE_WRITECOPY:
		return "rw-"
	case windows.PAGE_EXECUTE_READ:
		return "r-x"
	case windows.PAGE_EXECUTE_READWRITE, windows.PAGE_EXECUTE_WRITECOPY:
		return "rwx"
	default:
		return "r--"
	}
}

func (r *windowsMemReader) ReadAt(buf []byte, addr uint64) (int, error) {
	var nRead uintptr
	err := windows.ReadProcessMemory(r.handle, uintptr(addr), &buf[0], uintptr(len(buf)), &nRead)
	if err != nil {
		return int(nRead), err
	}
	return int(nRead), nil
}

func (r *windowsMemReader) Close() error {
	return windows.CloseHandle(r.handle)
}
