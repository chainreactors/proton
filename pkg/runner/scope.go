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
		logScope(cfg, "config", len(p))
	}
	if cfg.Home {
		p := sysinfo.HomePaths()
		paths = append(paths, p...)
		logScope(cfg, "home", len(p))
	}
	if cfg.Docker {
		p := sysinfo.DockerPaths()
		paths = append(paths, p...)
		logScope(cfg, "docker", len(p))
	}
	if cfg.Logs {
		p := sysinfo.LogsPaths()
		paths = append(paths, p...)
		logScope(cfg, "logs", len(p))
	}
	if cfg.Tmpfs {
		p := sysinfo.TmpfsPaths()
		paths = append(paths, p...)
		logScope(cfg, "tmpfs", len(p))
	}
	if cfg.History {
		p := sysinfo.HistoryFiles()
		paths = append(paths, p...)
		logScope(cfg, "history", len(p))
	}
	if cfg.Browser {
		p := sysinfo.BrowserPaths()
		paths = append(paths, p...)
		logScope(cfg, "browser", len(p))
	}
	if cfg.Coredump {
		p := sysinfo.CoredumpPaths()
		paths = append(paths, p...)
		logScope(cfg, "coredump", len(p))
	}

	return paths
}

func logScope(cfg *Config, name string, count int) {
	if !cfg.Quiet && count > 0 {
		logs.Log.Debugf("scope: %s → %d paths", name, count)
	}
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

func scanGitHistory(scanner *file.Scanner, targets []string, callback func(file.Finding)) {
	seen := make(map[string]bool)
	for _, target := range targets {
		if seen[target] {
			continue
		}
		seen[target] = true
		sysinfo.GitDeletedBlobs(target, func(data []byte, label string) {
			for _, group := range scanner.Groups {
				findings := scanner.ScanData(data, label, group)
				if len(findings) > 0 {
					atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
					for _, f := range findings {
						callback(f)
					}
				}
			}
		})
	}
}
