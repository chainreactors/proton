//go:build !(linux || windows || (darwin && cgo))

package sysinfo

import (
	"fmt"
	"runtime"
)

func NewMemoryReader(pid int) (MemoryReader, error) {
	return nil, fmt.Errorf("%s not supported on %s", "memory scanning", runtime.GOOS)
}
