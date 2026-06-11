//go:build !(linux || darwin || windows)

package sysinfo

import (
	"context"
	"fmt"
	"runtime"
)

func watchClipboard(ctx context.Context, onData func(data []byte, label string)) error {
	return fmt.Errorf("%s not supported on %s", "clipboard monitoring", runtime.GOOS)
}
