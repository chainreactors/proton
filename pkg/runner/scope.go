package runner

import (
	"sync/atomic"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
)

func expandScopeTargets(cfg *Config) []string {
	var paths []string

	if cfg.Config {
		p := sysinfo.ConfigPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: config → %d paths", len(p))
		}
	}

	if cfg.Docker {
		p := sysinfo.DockerKubePaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: docker/kube → %d paths", len(p))
		}
	}

	if cfg.Desktop {
		p := sysinfo.DesktopPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: desktop → %d paths", len(p))
		}
	}

	if cfg.Logs {
		p := sysinfo.LogsWebappPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: logs/webapp → %d paths", len(p))
		}
	}

	if cfg.Tmpfs {
		p := sysinfo.TmpfsPaths()
		paths = append(paths, p...)
		if !cfg.Quiet && len(p) > 0 {
			logs.Log.Debugf("scope: tmpfs → %d paths", len(p))
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
