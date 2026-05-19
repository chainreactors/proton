package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/protocols/file"
	"github.com/chainreactors/proton/templates"
	"gopkg.in/yaml.v3"
)

const banner = `
   ____                  __
  / __/__  __ _____  ___/ /
 / _// _ \/ // / _ \/ _  /
/_/  \___/\_,_/_//_/\_,_/  v0.1.0
`

func Run(opts *Options) error {
	if opts.List {
		return listTemplates(opts)
	}

	if opts.Input == "" {
		return fmt.Errorf("target (-i) is required")
	}
	if _, err := os.Stat(opts.Input); os.IsNotExist(err) {
		return fmt.Errorf("target not found: %s", opts.Input)
	}

	tmpls, err := loadTemplates(opts)
	if err != nil {
		return err
	}
	if len(tmpls) == 0 {
		return fmt.Errorf("no templates loaded")
	}

	out := os.Stdout
	var saveFile *os.File
	if opts.SaveFile != "" {
		f, err := os.Create(opts.SaveFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %v", err)
		}
		defer f.Close()
		saveFile = f
	}

	outputFormat := opts.Output
	if opts.JSON {
		outputFormat = "json"
	}

	if !opts.Quiet && outputFormat == "text" {
		logs.Log.Console(banner)
		mode := "TextOnly"
		if opts.Bin {
			mode = "Binary: on"
		}
		logs.Log.Infof("Loaded %d templates | Target: %s | %s", len(tmpls), opts.Input, mode)
		logs.Log.Infof("Scanning...")
	}

	writer := newOutputWriter(outputFormat, out, opts.Input)
	var saveWriter *outputWriter
	if saveFile != nil {
		saveWriter = newOutputWriter(outputFormat, saveFile, opts.Input)
	}

	sevFilter := parseSeverityFilter(opts.Severity)
	start := time.Now()
	var findingCount int
	sevCount := map[string]int{}
	seen := map[string]bool{}
	var allFindings []Finding

	// Build unified scanner inputs from loaded templates
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !opts.Bin},
	}
	var inputs []file.Rule
	for _, tmpl := range tmpls {
		inputs = append(inputs, file.Rule{
			ID:       tmpl.Id,
			Name:     tmpl.Info.Name,
			Severity: tmpl.Info.Severity,
			Requests: tmpl.RequestsFile,
		})
	}

	scanner := file.NewScanner(inputs, execOpts)
	scanner.Scan(opts.Input, func(uf file.Finding) {
		f := Finding{
			TemplateID:   uf.TemplateID,
			TemplateName: uf.TemplateName,
			Severity:     uf.Severity,
			FilePath:     uf.FilePath,
			Matches:      uf.Matches,
			Extracts:     uf.Extracts,
		}
		for name := range uf.Matches {
			f.MatcherName = name
			break
		}

		if len(sevFilter) > 0 {
			if _, ok := sevFilter[f.Severity]; !ok {
				return
			}
		}

		key := f.TemplateID + "|" + f.FilePath
		if seen[key] {
			return
		}
		seen[key] = true

		findingCount++
		sevCount[f.Severity]++
		if opts.Collect != "" {
			allFindings = append(allFindings, f)
		}
		writer.WriteFinding(f)
		if saveWriter != nil {
			saveWriter.WriteFinding(f)
		}
	})

	elapsed := time.Since(start)
	if !opts.Quiet && outputFormat == "text" {
		printSummary(len(tmpls), findingCount, elapsed, sevCount)
	}

	if saveFile != nil && !opts.Quiet {
		logs.Log.Infof("Results saved to %s", opts.SaveFile)
	}

	if opts.Collect != "" && len(allFindings) > 0 {
		copts := collectOpts{
			ZipPath:  opts.Collect,
			Password: opts.Key,
			BaseDir:  opts.Input,
			KeepTree: opts.CollectTree,
			Findings: allFindings,
		}
		if err := collectFiles(copts); err != nil {
			return fmt.Errorf("collect files: %v", err)
		}
	}

	return nil
}

func loadTemplates(opts *Options) ([]*templates.Template, error) {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !opts.Bin},
	}

	excludePaths := make(map[string]bool)
	for _, p := range opts.ExcludeTemplates {
		abs, err := filepath.Abs(p)
		if err == nil {
			excludePaths[abs] = true
		}
	}

	var tmpls []*templates.Template

	loadFiltered := func(path string) error {
		loaded, err := loadFromPath(path, execOpts)
		if err != nil {
			return err
		}
		for _, t := range loaded {
			tmpls = append(tmpls, t)
		}
		return nil
	}

	for _, tmplPath := range opts.Templates {
		if abs, err := filepath.Abs(tmplPath); err == nil && excludePaths[abs] {
			continue
		}
		if err := loadFiltered(tmplPath); err != nil {
			return nil, fmt.Errorf("loading template %s: %v", tmplPath, err)
		}
	}

	if len(opts.Templates) == 0 {
		for _, cat := range opts.Categories {
			catDir := filepath.Join(opts.TemplateDir, cat)
			if _, err := os.Stat(catDir); os.IsNotExist(err) {
				return nil, fmt.Errorf("category directory not found: %s", catDir)
			}
			loadFiltered(catDir)
		}
	}

	tmpls = filterTemplates(tmpls, opts)
	return tmpls, nil
}

func loadFromPath(path string, execOpts *protocols.ExecuterOptions) ([]*templates.Template, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		tmpl, err := loadSingleTemplate(path, execOpts)
		if err != nil {
			return nil, err
		}
		return []*templates.Template{tmpl}, nil
	}

	var tmpls []*templates.Template
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		tmpl, err := loadSingleTemplate(p, execOpts)
		if err != nil {
			return nil
		}
		tmpls = append(tmpls, tmpl)
		return nil
	})
	return tmpls, nil
}

func loadSingleTemplate(path string, execOpts *protocols.ExecuterOptions) (*templates.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tmpl templates.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse %s: %v", path, err)
	}
	if len(tmpl.RequestsFile) == 0 {
		return nil, fmt.Errorf("no file requests in %s", path)
	}
	if err := tmpl.Compile(execOpts); err != nil {
		return nil, fmt.Errorf("compile %s: %v", path, err)
	}
	return &tmpl, nil
}

func filterTemplates(tmpls []*templates.Template, opts *Options) []*templates.Template {
	includeTags := toSet(opts.Tags)
	excludeTags := toSet(opts.ExcludeTags)
	includeIDs := toSet(opts.TemplateIDs)
	excludeIDs := toSet(opts.ExcludeIDs)

	if len(includeTags) == 0 && len(excludeTags) == 0 &&
		len(includeIDs) == 0 && len(excludeIDs) == 0 {
		return tmpls
	}

	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		if len(excludeIDs) > 0 && excludeIDs[tmpl.Id] {
			continue
		}
		if len(includeIDs) > 0 && !includeIDs[tmpl.Id] {
			continue
		}

		tags := tmpl.GetTags()

		if len(excludeTags) > 0 && matchAnyTag(tags, excludeTags) {
			continue
		}
		if len(includeTags) > 0 && !matchAnyTag(tags, includeTags) {
			continue
		}

		filtered = append(filtered, tmpl)
	}
	return filtered
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[strings.TrimSpace(strings.ToLower(item))] = true
	}
	return s
}

func matchAnyTag(tags []string, set map[string]bool) bool {
	for _, tag := range tags {
		if set[strings.TrimSpace(strings.ToLower(tag))] {
			return true
		}
	}
	return false
}

func parseSeverityFilter(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, sev := range strings.Split(s, ",") {
		m[strings.TrimSpace(strings.ToLower(sev))] = true
	}
	return m
}

func listTemplates(opts *Options) error {
	paths := opts.Templates
	if len(paths) == 0 {
		for _, cat := range opts.Categories {
			paths = append(paths, filepath.Join(opts.TemplateDir, cat))
		}
	}

	logs.Log.Console("Available templates:\n\n")
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			logs.Log.Warnf("template not found: %s", path)
			continue
		}
		if !info.IsDir() {
			printTemplateInfo(path)
			continue
		}
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
				return nil
			}
			printTemplateInfo(p)
			return nil
		})
	}
	return nil
}

func printTemplateInfo(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var tmpl templates.Template
	if yaml.Unmarshal(data, &tmpl) != nil {
		return
	}
	if len(tmpl.RequestsFile) == 0 {
		return
	}
	sev := tmpl.Info.Severity
	if sev == "" {
		sev = "unknown"
	}
	fmt.Printf("  %-8s %-35s %s\n", sev, tmpl.Id, tmpl.Info.Name)
}
