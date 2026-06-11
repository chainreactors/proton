//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

func listProcesses() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("process enumeration not supported on %s", runtime.GOOS)
}
