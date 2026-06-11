//go:build windows
// +build windows

package sysinfo

import (
	"context"
	"crypto/sha256"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procOpenCB       = user32.NewProc("OpenClipboard")
	procCloseCB      = user32.NewProc("CloseClipboard")
	procGetCBData    = user32.NewProc("GetClipboardData")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

const cfUnicodeText = 13

func watchClipboard(ctx context.Context, onData func(data []byte, label string)) error {
	var lastHash [32]byte
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			data := readWindowsClipboard()
			if len(data) == 0 {
				continue
			}
			hash := sha256.Sum256(data)
			if hash == lastHash {
				continue
			}
			lastHash = hash
			onData(data, "clipboard")
		}
	}
}

func readWindowsClipboard() []byte {
	ret, _, _ := procOpenCB.Call(0)
	if ret == 0 {
		return nil
	}
	defer procCloseCB.Call()

	h, _, _ := procGetCBData.Call(cfUnicodeText)
	if h == 0 {
		return nil
	}

	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return nil
	}
	defer procGlobalUnlock.Call(h)

	// Read UTF-16LE until double null
	var result []byte
	for i := uintptr(0); i < 1<<20; i += 2 {
		ch := *(*uint16)(unsafe.Pointer(ptr + i))
		if ch == 0 {
			break
		}
		if ch < 128 {
			result = append(result, byte(ch))
		}
	}
	return result
}
