//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

func ReadProcessEnv(pid int) ([]byte, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process data reading", runtime.GOOS)
}

func ReadProcessCmdline(pid int) ([]byte, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process data reading", runtime.GOOS)
}

func ReadProcessFDs(pid int) ([]byte, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process data reading", runtime.GOOS)
}

func ReadProcessConns(pid int) ([]byte, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process data reading", runtime.GOOS)
}

func ReadProcessPipes(pid int) ([]byte, error) {
	return nil, fmt.Errorf("%s not supported on %s", "process data reading", runtime.GOOS)
}
