package runner

import (
	"fmt"
	"sync/atomic"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
	"github.com/chainreactors/proton/sysinfo"
)

func resolveTargetPIDs(cfg *Config) ([]int, error) {
	if cfg.PID > 0 {
		return []int{cfg.PID}, nil
	}
	procs, err := sysinfo.ListProcesses()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, p := range procs {
		if sysinfo.MatchProcess(p.Name, cfg.Process) {
			pids = append(pids, p.PID)
		}
	}
	return pids, nil
}

func scanProcessSources(scanner *file.Scanner, execOpts *protocols.ExecuterOptions, pid int, sources []string, callback func(file.Finding), quiet bool, format string) {
	for _, src := range sources {
		data, err := sysinfo.ReadSource(pid, src)
		if err != nil || len(data) == 0 {
			continue
		}
		label := fmt.Sprintf("pid:%d:%s", pid, src)
		if !quiet && format == "text" {
			logs.Log.Debugf("scanning pid:%d source:%s (%d bytes)", pid, src, len(data))
		}
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
}

type sysRule struct {
	ID       string
	Name     string
	Severity string
	Request  *sys.Request
	FileReq  *file.Request
}

func buildSysScanner(rules []sysRule, execOpts *protocols.ExecuterOptions) *file.Scanner {
	var inputs []file.Rule
	for _, mr := range rules {
		var fileReqs []*file.Request
		if mr.FileReq != nil {
			fileReqs = []*file.Request{mr.FileReq}
		} else if mr.Request != nil && mr.Request.CompiledOperators != nil {
			req := &file.Request{
				Extensions: []string{"all"},
			}
			req.Matchers = mr.Request.Matchers
			req.Extractors = mr.Request.Extractors
			req.Compile(execOpts)
			fileReqs = []*file.Request{req}
		}
		if len(fileReqs) > 0 {
			inputs = append(inputs, file.Rule{
				ID:       mr.ID,
				Name:     mr.Name,
				Severity: mr.Severity,
				Requests: fileReqs,
			})
		}
	}
	if len(inputs) == 0 {
		return nil
	}
	return file.NewScanner(inputs, execOpts)
}

func scanProcessWithSysRules(rules []sysRule, execOpts *protocols.ExecuterOptions, pid int, callback func(file.Finding)) error {
	memoryRules := make([]sysRule, 0)
	dataRules := make([]sysRule, 0)
	for _, r := range rules {
		src := sysinfo.SourceMemory
		if r.Request != nil {
			src = r.Request.Source
		}
		if src == sysinfo.SourceMemory {
			memoryRules = append(memoryRules, r)
		} else {
			dataRules = append(dataRules, r)
		}
	}

	if len(dataRules) > 0 {
		dataScanner := buildSysScanner(dataRules, execOpts)
		if dataScanner != nil {
			for _, rule := range dataRules {
				src := rule.Request.Source
				data, err := sysinfo.ReadSource(pid, src)
				if err != nil || len(data) == 0 {
					continue
				}
				label := fmt.Sprintf("pid:%d:%s", pid, src)
				for _, group := range dataScanner.Groups {
					findings := dataScanner.ScanData(data, label, group)
					if len(findings) > 0 {
						atomic.AddInt64(&dataScanner.Stats.Findings, int64(len(findings)))
						for _, f := range findings {
							callback(f)
						}
					}
				}
			}
		}
	}

	if len(memoryRules) > 0 {
		scanner := buildSysScanner(memoryRules, execOpts)
		if scanner == nil {
			return nil
		}

		regionFilter := func(r sysinfo.MemoryRegion) bool {
			for _, mr := range memoryRules {
				if mr.Request != nil && mr.Request.MatchesRegion(r.Perms, r.MappedFile) {
					return true
				}
				if mr.FileReq != nil && sysinfo.ShouldScanRegion(r, false) {
					return true
				}
			}
			return false
		}

		opts := sysinfo.MemScanOptions{
			OverlapSize:  file.MemOverlapSize,
			RegionFilter: regionFilter,
		}

		return sysinfo.WalkProcessMemory(pid, opts, func(data []byte, label string) {
			atomic.AddInt64(&scanner.Stats.Bytes, int64(len(data)))
			for _, group := range scanner.Groups {
				findings := scanner.ScanBlock(data, label, group)
				if len(findings) > 0 {
					atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
					for _, f := range findings {
						callback(f)
					}
				}
			}
		})
	}

	return nil
}

func scanProcess(scanner *file.Scanner, pid int, scanAll bool, callback func(file.Finding)) error {
	opts := sysinfo.MemScanOptions{
		ScanAll:     scanAll,
		OverlapSize: file.MemOverlapSize,
	}

	return sysinfo.WalkProcessMemory(pid, opts, func(data []byte, label string) {
		atomic.AddInt64(&scanner.Stats.Bytes, int64(len(data)))
		for _, group := range scanner.Groups {
			findings := scanner.ScanBlock(data, label, group)
			if len(findings) > 0 {
				atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
				for _, f := range findings {
					callback(f)
				}
			}
		}
	})
}
