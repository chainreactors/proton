//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

func listProcesses() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process enumeration", runtime.GOOS)
}
