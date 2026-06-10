//go:build !(linux || windows || darwin)

package cmd

import (
	"fmt"
	"runtime"
)

func openCapture(iface string) (captureHandle, error) {
	return nil, fmt.Errorf("network capture is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
