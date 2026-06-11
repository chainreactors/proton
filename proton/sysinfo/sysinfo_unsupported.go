//go:build !(linux || windows || darwin)

package sysinfo

import (
	"fmt"
	"runtime"
)

func ReadProcessEnv(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func ReadProcessCmdline(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func ReadProcessFDs(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func ReadProcessConns(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func ReadProcessPipes(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}
