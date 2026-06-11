package runner

import (
	"sync/atomic"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
)

func scanRegistry(scanner *file.Scanner, opts sysinfo.RegistryWalkOptions, callback func(file.Finding)) error {
	if scanner == nil || len(scanner.Groups) == 0 {
		return nil
	}
	return sysinfo.WalkRegistry(opts, func(value sysinfo.RegistryValue) error {
		data := value.Record()
		label := value.Label()
		atomic.AddInt64(&scanner.Stats.Bytes, int64(len(data)))
		for _, group := range scanner.Groups {
			findings := scanner.ScanData(data, label, group)
			if len(findings) > 0 {
				atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
				for _, finding := range findings {
					callback(finding)
				}
			}
		}
		return nil
	})
}

func scanRegistryWithSysRules(rules []sysRule, execOpts *protocols.ExecuterOptions, callback func(file.Finding)) error {
	for _, rule := range rules {
		if rule.Request == nil || rule.Request.Source != sysinfo.SourceRegistry {
			continue
		}
		scanner := buildSysScanner([]sysRule{rule}, execOpts)
		if scanner == nil {
			continue
		}
		opts := rule.Request.RegistryOptions()
		if err := scanRegistry(scanner, opts, callback); err != nil {
			return err
		}
	}
	return nil
}

func defaultRegistryOptionsFromConfig(cfg *Config) sysinfo.RegistryWalkOptions {
	opts := sysinfo.DefaultRegistryWalkOptions()
	opts.Hives = append([]string(nil), cfg.RegistryHives...)
	if !cfg.Registry {
		opts.Targets = nil
	}
	return opts
}
