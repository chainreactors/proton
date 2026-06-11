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

type MemoryRegion struct {
	BaseAddr   uint64
	Size       uint64
	Perms      string
	MappedFile string
}

type MemoryReader interface {
	Regions() ([]MemoryRegion, error)
	ReadAt(buf []byte, addr uint64) (int, error)
	Close() error
}

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
