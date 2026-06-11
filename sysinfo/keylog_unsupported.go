//go:build !(linux || windows || (darwin && cgo))

package sysinfo

import (
	"context"
	"fmt"
	"runtime"
)

func watchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	return fmt.Errorf("%s not supported on %s", "keystroke monitoring", runtime.GOOS)
}
