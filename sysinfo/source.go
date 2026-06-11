package sysinfo

import "fmt"

const (
	SourceMemory   = "memory"
	SourceEnv      = "env"
	SourceCmdline  = "cmdline"
	SourceFD       = "fd"
	SourceConn     = "conn"
	SourcePipe     = "pipe"
	SourceRegistry = "registry"
)

func ReadSource(pid int, source string) ([]byte, error) {
	switch source {
	case SourceEnv:
		return ReadProcessEnv(pid)
	case SourceCmdline:
		return ReadProcessCmdline(pid)
	case SourceFD:
		return ReadProcessFDs(pid)
	case SourceConn:
		return ReadProcessConns(pid)
	case SourcePipe:
		return ReadProcessPipes(pid)
	case SourceRegistry:
		return nil, fmt.Errorf("registry source requires WalkRegistry")
	default:
		return nil, fmt.Errorf("unknown sys source: %s", source)
	}
}
