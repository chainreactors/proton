//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

// OpenCapture returns an error on unsupported platforms.
func OpenCapture(iface string) (CaptureHandle, error) {
	return nil, fmt.Errorf("%s not supported on %s", "network capture", runtime.GOOS)
}
