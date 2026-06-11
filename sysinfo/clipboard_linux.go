//go:build linux
// +build linux

package sysinfo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"time"
)

func watchClipboard(ctx context.Context, onData func(data []byte, label string)) error {
	tool := findClipboardTool()
	if tool == "" {
		return fmt.Errorf("no clipboard tool found (install xclip or xsel)")
	}

	var lastHash [32]byte
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			data, err := readClipboard(tool)
			if err != nil || len(data) == 0 {
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

func findClipboardTool() string {
	for _, tool := range []string{"xclip", "xsel", "wl-paste"} {
		if _, err := exec.LookPath(tool); err == nil {
			return tool
		}
	}
	return ""
}

func readClipboard(tool string) ([]byte, error) {
	switch tool {
	case "xclip":
		return exec.Command("xclip", "-selection", "clipboard", "-o").Output()
	case "xsel":
		return exec.Command("xsel", "--clipboard", "--output").Output()
	case "wl-paste":
		return exec.Command("wl-paste", "--no-newline").Output()
	}
	return nil, nil
}
