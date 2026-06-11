//go:build linux
// +build linux

package sysinfo

import (
	"os"
	"strings"
)

// ReadKeyring reads the kernel keyring entries visible to the current process.
// Returns the content of /proc/keys as newline-separated text.
func ReadKeyring() ([]byte, error) {
	data, err := os.ReadFile("/proc/keys")
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	return data, nil
}
