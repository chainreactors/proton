//go:build !linux

package sysinfo

// ReadKeyring is not available on non-Linux platforms.
func ReadKeyring() ([]byte, error) {
	return nil, nil
}
