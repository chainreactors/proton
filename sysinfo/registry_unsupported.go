//go:build !windows

package sysinfo

import (
	"fmt"
	"runtime"
)

func WalkRegistry(opts RegistryWalkOptions, cb func(RegistryValue) error) error {
	return unsupportedRegistryError()
}

func unsupportedRegistryError() error {
	return fmt.Errorf("%s not supported on %s", "registry scanning", runtime.GOOS)
}
