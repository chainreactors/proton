package sysinfo

import "strings"

type ProcessInfo struct {
	PID  int
	Name string
}

// ListProcesses returns all accessible processes on the system.
func ListProcesses() ([]ProcessInfo, error) {
	return listProcesses()
}

// MatchProcess returns true if the process name contains the given substring (case-insensitive).
func MatchProcess(procName, pattern string) bool {
	if pattern == "" {
		return true
	}
	return strings.Contains(strings.ToLower(procName), strings.ToLower(pattern))
}
