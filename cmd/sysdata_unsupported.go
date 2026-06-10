//go:build !(linux || windows || darwin)

package cmd

import (
	"fmt"
	"runtime"
)

func readProcessEnv(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func readProcessCmdline(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func readProcessFDs(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func readProcessConns(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}

func readProcessPipes(pid int) ([]byte, error) {
	return nil, fmt.Errorf("sys data reading not supported on %s", runtime.GOOS)
}
