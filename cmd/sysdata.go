package cmd

import (
	"fmt"

	"github.com/chainreactors/proton/proton/sys"
)

func readSysData(pid int, source string) ([]byte, error) {
	switch source {
	case sys.SourceEnv:
		return readProcessEnv(pid)
	case sys.SourceCmdline:
		return readProcessCmdline(pid)
	case sys.SourceFD:
		return readProcessFDs(pid)
	case sys.SourceConn:
		return readProcessConns(pid)
	case sys.SourcePipe:
		return readProcessPipes(pid)
	default:
		return nil, fmt.Errorf("unknown sys source: %s", source)
	}
}
