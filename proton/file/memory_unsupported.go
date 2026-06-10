//go:build !(linux || windows || (darwin && cgo))

package file

import (
	"fmt"
	"runtime"
)

func newMemoryReader(pid int) (MemoryReader, error) {
	return nil, fmt.Errorf("process memory scanning is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
