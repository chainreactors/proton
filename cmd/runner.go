package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/protocols/file"
	"github.com/chainreactors/proton/templates"
	"gopkg.in/yaml.v3"
)

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

	if !opts.Quiet && opts.Output == "text" {
		printBanner(out)
		mode := " | TextOnly"
		if opts.Bin {
			mode = " | Binary: on"
		}
		fmt.Fprintf(out, "[INF] Loaded %d templates | Target: %s%s\n", len(tmpls), opts.Input, mode)
		fmt.Fprintf(out, "[INF] Scanning...\n\n")
	}

	writer := newOutputWriter(opts.Output, out, opts.Input)
	var saveWriter *outputWriter
	if saveFile != nil {
		saveWriter = newOutputWriter(opts.Output, saveFile, opts.Input)
	}

	sevFilter := parseSeverityFilter(opts.Severity)
	start := time.Now()
	var findingCount int
	sevCount := map[string]int{}
	seen := map[string]bool{}

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
		}
		if uf.Result != nil {
			for _, e := range uf.Result.OutputExtracts {
				f.Extracts = append(f.Extracts, e)
			}
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
		writer.WriteFinding(f)
		if saveWriter != nil {
			saveWriter.WriteFinding(f)
		}
	})

	elapsed := time.Since(start)
	if !opts.Quiet && opts.Output == "text" {
		printSummary(out, len(tmpls), findingCount, elapsed, sevCount)
	}

	if saveFile != nil && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "[INF] Results saved to %s\n", opts.SaveFile)
	}

	return nil
}

func loadTemplates(opts *Options) ([]*templates.Template, error) {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !opts.Bin},
	}

	var tmpls []*templates.Template

	for _, tmplPath := range opts.Templates {
		loaded, err := loadFromPath(tmplPath, execOpts)
		if err != nil {
			return nil, fmt.Errorf("loading template %s: %v", tmplPath, err)
		}
		tmpls = append(tmpls, loaded...)
	}

	if len(opts.Templates) == 0 {
		for _, cat := range opts.Categories {
			catDir := filepath.Join(opts.TemplateDir, cat)
			if _, err := os.Stat(catDir); os.IsNotExist(err) {
				return nil, fmt.Errorf("category directory not found: %s", catDir)
			}
			loaded, _ := loadFromPath(catDir, execOpts)
			tmpls = append(tmpls, loaded...)
		}
	}

	if len(opts.Tags) > 0 {
		tmpls = filterByTags(tmpls, opts.Tags)
	}

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

func filterByTags(tmpls []*templates.Template, tags []string) []*templates.Template {
	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.TrimSpace(t)] = true
	}
	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		for _, tag := range tmpl.GetTags() {
			if tagSet[strings.TrimSpace(tag)] {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}
	return filtered
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

	fmt.Println("Available templates:")
	fmt.Println()
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not found: %s\n", path)
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
