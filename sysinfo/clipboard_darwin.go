//go:build darwin
// +build darwin

package sysinfo

import (
	"context"
	"crypto/sha256"
	"os/exec"
	"time"
)

func watchClipboard(ctx context.Context, onData func(data []byte, label string)) error {
	var lastHash [32]byte
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			data, err := exec.Command("pbpaste").Output()
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
