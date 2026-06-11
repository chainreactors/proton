//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

// OpenCapture returns an error on unsupported platforms.
func OpenCapture(iface string) (CaptureHandle, error) {
	return nil, fmt.Errorf("network capture is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
