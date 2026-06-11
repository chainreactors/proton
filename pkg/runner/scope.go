package runner

import (
	"sync/atomic"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
)

// expandScopeTargets resolves --shm, --tmpfs, --history flags into file paths.
func expandScopeTargets(cfg *Config) []string {
	var paths []string

	if cfg.Shm {
		p := sysinfo.ShmPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: shm → %v", p)
		}
	}

	if cfg.Tmpfs {
		p := sysinfo.TmpfsPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: tmpfs → %v", p)
		}
	}

	if cfg.History {
		p := sysinfo.HistoryFiles()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: history → %d files", len(p))
		}
	}

	return paths
}

// scanKeyring reads kernel keyring and scans with the scanner.
func scanKeyring(scanner *file.Scanner, callback func(file.Finding)) {
	data, err := sysinfo.ReadKeyring()
	if err != nil || len(data) == 0 {
		return
	}
	label := "keyring:/proc/keys"
	for _, group := range scanner.Groups {
		findings := scanner.ScanData(data, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				callback(f)
			}
		}
	}
}
