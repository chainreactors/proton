//go:build !(linux || windows || (darwin && cgo))

package sysinfo

import (
	"context"
	"fmt"
	"runtime"
)

func watchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	return fmt.Errorf("keystroke monitoring not supported on %s", runtime.GOOS)
}
