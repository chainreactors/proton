package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

var validIDPattern = regexp.MustCompile(`^[a-zA-Z0-9]+([_-][a-zA-Z0-9]+)*$`)

func runTemplateDisplay(opts *Options) error {
	useColor := isTTY(os.Stdout) && !opts.NoColor
	if useColor {
		logs.Log.SetColor(true)
	}

	query := opts.Display

	// If it looks like a file path, read directly
	if strings.HasSuffix(query, ".yaml") || strings.HasSuffix(query, ".yml") || strings.Contains(query, string(os.PathSeparator)) {
		data, err := os.ReadFile(query)
		if err != nil {
			return fmt.Errorf("cannot read template: %v", err)
		}
		fmt.Print(string(data))
		return nil
	}

	// Search by template ID in local templates, then embedded
	if data := findTemplateByID(query, opts); data != nil {
		fmt.Print(string(data))
		return nil
	}

	return fmt.Errorf("template %q not found (specify a file path or a valid template ID)", query)
}

func findTemplateByID(id string, opts *Options) []byte {
	// Search in local template directory
	tmplDir := resolveTemplateDir(opts)
	if data := findTemplateInDir(id, tmplDir); data != nil {
		return data
	}

	// Search in -t paths
	for _, path := range opts.Templates {
		if data := findTemplateInDir(id, path); data != nil {
			return data
		}
	}

	// Search in embedded templates
	for _, config := range embeddedTemplateConfigs([]string{"all"}) {
		raw := pkg.LoadConfig(config)
		if len(raw) == 0 {
			continue
		}
		var pocs []interface{}
		if yaml.Unmarshal(raw, &pocs) != nil {
			continue
		}
		for _, poc := range pocs {
			bs, err := yaml.Marshal(poc)
			if err != nil {
				continue
			}
			var tmpl template.Template
			if yaml.Unmarshal(bs, &tmpl) != nil {
				continue
			}
			if tmpl.Id == id {
				return bs
			}
		}
	}
	return nil
}

func findTemplateInDir(id, dir string) []byte {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	var found []byte
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found != nil {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var tmpl template.Template
		if yaml.Unmarshal(data, &tmpl) == nil && tmpl.Id == id {
			found = data
		}
		return nil
	})
	return found
}

var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
	"unknown":  true,
}

type validateResult struct {
	path     string
	id       string
	valid    bool
	errors   []string
	warnings []string
}

func runValidate(opts *Options) error {
	useColor := isTTY(os.Stdout) && !opts.NoColor
	if useColor {
		logs.Log.SetColor(true)
	}

	if !opts.Quiet {
		logs.Log.Console(banner)
	}

	var results []validateResult

	if len(opts.Templates) > 0 {
		for _, tmplPath := range opts.Templates {
			results = append(results, validatePath(tmplPath)...)
		}
	} else {
		results = append(results, validateEmbedded()...)
	}

	var validCount, invalidCount, warnCount int
	for _, r := range results {
		if !r.valid {
			invalidCount++
			for _, e := range r.errors {
				logs.Log.Errorf("%s: %s", r.path, e)
			}
		} else {
			validCount++
		}
		if len(r.warnings) > 0 {
			warnCount++
			for _, w := range r.warnings {
				logs.Log.Warnf("%s: %s", r.path, w)
			}
		}
	}

	logs.Log.Console(strings.Repeat("─", 60) + "\n")
	if invalidCount == 0 {
		logs.Log.Infof("All %d templates are valid", validCount)
	} else {
		logs.Log.Infof("Validated %d templates: %d valid, %d invalid", len(results), validCount, invalidCount)
	}
	if warnCount > 0 {
		logs.Log.Warnf("%d template(s) with warnings", warnCount)
	}

	if invalidCount > 0 {
		return fmt.Errorf("validation failed: %d invalid template(s)", invalidCount)
	}
	return nil
}

func validatePath(path string) []validateResult {
	info, err := os.Stat(path)
	if err != nil {
		return []validateResult{{path: path, errors: []string{fmt.Sprintf("cannot access: %v", err)}}}
	}

	if !info.IsDir() {
		r := validateSingleFile(path)
		return []validateResult{r}
	}

	var results []validateResult
	filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		results = append(results, validateSingleFile(p))
		return nil
	})
	return results
}

func validateSingleFile(path string) validateResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return validateResult{path: path, errors: []string{fmt.Sprintf("read error: %v", err)}}
	}
	return validateTemplateData(path, data)
}

func validateEmbedded() []validateResult {
	var results []validateResult
	for _, config := range embeddedTemplateConfigs([]string{"all"}) {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if err := yaml.Unmarshal(data, &pocs); err != nil {
			results = append(results, validateResult{
				path:   "embedded:" + config,
				errors: []string{fmt.Sprintf("parse embedded data: %v", err)},
			})
			continue
		}

		for i, poc := range pocs {
			bs, err := yaml.Marshal(poc)
			if err != nil {
				results = append(results, validateResult{
					path:   fmt.Sprintf("embedded:%s[%d]", config, i),
					errors: []string{fmt.Sprintf("marshal error: %v", err)},
				})
				continue
			}
			r := validateTemplateData(fmt.Sprintf("embedded:%s[%d]", config, i), bs)
			if r.id != "" {
				r.path = fmt.Sprintf("embedded:%s", r.id)
			}
			results = append(results, r)
		}
	}
	if len(results) == 0 {
		return []validateResult{{path: "embedded", errors: []string{"no embedded templates found"}}}
	}
	return results
}

func validateTemplateData(name string, data []byte) validateResult {
	r := validateResult{path: name, valid: true}

	var tmpl template.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		r.valid = false
		r.errors = append(r.errors, fmt.Sprintf("YAML parse error: %v", err))
		return r
	}

	r.id = tmpl.Id

	if tmpl.Id == "" {
		r.valid = false
		r.errors = append(r.errors, "missing required field \"id\"")
	} else if !validIDPattern.MatchString(tmpl.Id) {
		r.warnings = append(r.warnings, fmt.Sprintf("id %q does not match recommended pattern [a-zA-Z0-9_-]", tmpl.Id))
	}

	if tmpl.Info.Name == "" {
		r.valid = false
		r.errors = append(r.errors, "missing required field \"info.name\"")
	}

	if len(tmpl.RequestsFile) == 0 && len(tmpl.RequestsSys) == 0 {
		r.valid = false
		r.errors = append(r.errors, "no file or sys requests defined")
	}

	sev := strings.ToLower(tmpl.Info.Severity)
	if sev == "" {
		r.warnings = append(r.warnings, "missing info.severity field")
	} else if !validSeverities[sev] {
		r.valid = false
		r.errors = append(r.errors, fmt.Sprintf("invalid severity %q, must be one of: critical, high, medium, low, info, unknown", tmpl.Info.Severity))
	}

	if len(tmpl.RequestsFile) > 0 {
		execOpts := &protocols.ExecuterOptions{
			Options: &protocols.Options{TextOnly: true},
		}
		if err := tmpl.Compile(execOpts); err != nil {
			r.valid = false
			r.errors = append(r.errors, fmt.Sprintf("compile error: %v", err))
		}
	}

	if tmpl.Info.Tags == "" {
		r.warnings = append(r.warnings, "no tags defined")
	}

	return r
}
