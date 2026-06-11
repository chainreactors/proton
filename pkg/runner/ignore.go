package runner

import (
	"os"
	"path/filepath"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/pkg"
	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

// ignoreConfig holds post-scan suppression rules for reviewed findings.
//
// This is distinct from pre-scan exclusions (--exclude-id, --etags, extension/directory filters)
// which prevent files or templates from being scanned at all.
// Ignore rules apply AFTER a finding is produced — they suppress known false positives
// or accepted risks that have been reviewed by the user.
type ignoreConfig struct {
	Rules []ignoreRule `yaml:"rules"`
}

type ignoreRule struct {
	ID     string   `yaml:"id"`
	Paths  []string `yaml:"paths"`
	Reason string   `yaml:"reason"`
}

type compiledIgnore struct {
	id    glob.Glob
	paths []glob.Glob
}

type ignoreFilter struct {
	rules      []compiledIgnore
	suppressed int
}

func loadIgnoreFilter(targets []string, extraPaths []string) *ignoreFilter {
	var allRules []ignoreRule

	for _, target := range targets {
		dir := target
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			dir = filepath.Dir(target)
		}
		if rules := loadIgnoreFile(filepath.Join(dir, ".foundignore.yaml")); rules != nil {
			allRules = append(allRules, rules...)
		}
	}

	for _, p := range extraPaths {
		if rules := loadIgnoreFile(p); rules != nil {
			allRules = append(allRules, rules...)
		} else {
			logs.Log.Warnf("cannot load ignore file: %s", p)
		}
	}

	if data := pkg.LoadConfig("found_ignore"); len(data) > 0 {
		var cfg ignoreConfig
		if yaml.Unmarshal(data, &cfg) == nil {
			allRules = append(allRules, cfg.Rules...)
		}
	}

	if len(allRules) == 0 {
		return nil
	}

	var compiled []compiledIgnore
	for _, r := range allRules {
		cr := compiledIgnore{}
		if r.ID != "" {
			if g, err := glob.Compile(r.ID); err == nil {
				cr.id = g
			}
		}
		for _, p := range r.Paths {
			if g, err := glob.Compile(p); err == nil {
				cr.paths = append(cr.paths, g)
			}
		}
		if cr.id != nil || len(cr.paths) > 0 {
			compiled = append(compiled, cr)
		}
	}

	if len(compiled) == 0 {
		return nil
	}
	return &ignoreFilter{rules: compiled}
}

func loadIgnoreFile(path string) []ignoreRule {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg ignoreConfig
	if yaml.Unmarshal(data, &cfg) != nil {
		return nil
	}
	return cfg.Rules
}

// shouldIgnore checks whether a produced finding should be suppressed.
// This runs after the scan — the file was already scanned and the finding was already matched.
func (f *ignoreFilter) shouldIgnore(templateID, relPath string) bool {
	if f == nil {
		return false
	}
	for _, rule := range f.rules {
		if rule.id != nil && !rule.id.Match(templateID) {
			continue
		}
		if len(rule.paths) == 0 {
			f.suppressed++
			return true
		}
		for _, g := range rule.paths {
			if g.Match(relPath) {
				f.suppressed++
				return true
			}
		}
	}
	return false
}
