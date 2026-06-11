//go:build windows

package sysinfo

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func listProcesses() ([]ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snap, &entry)
	if err != nil {
		return nil, err
	}

	var procs []ProcessInfo
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, ProcessInfo{
			PID:  int(entry.ProcessID),
			Name: name,
		})
		err = windows.Process32Next(snap, &entry)
		if err != nil {
			break
		}
	}
	return procs, nil
}
