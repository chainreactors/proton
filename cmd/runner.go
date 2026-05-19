package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chainreactors/found/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/operators"
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

	var targets []string
	if opts.Auto {
		autoTargets := loadAutoTargets()
		targets = append(targets, autoTargets...)
	}
	if opts.Input != "" {
		targets = append(targets, opts.Input)
	}
	if len(targets) == 0 {
		return fmt.Errorf("target (-i) or --auto is required")
	}

	var tmpls []*templates.Template
	hasExplicitTemplates := len(opts.Templates) > 0
	expressionMode := len(opts.Expressions) > 0
	if hasExplicitTemplates || !expressionMode {
		var err error
		tmpls, err = loadTemplates(opts)
		if err != nil {
			return err
		}
	}
	if len(tmpls) == 0 && len(opts.Expressions) == 0 {
		return fmt.Errorf("no templates loaded and no expressions specified")
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
		logs.Log.Infof("Loaded %d templates | Targets: %d | %s", len(tmpls), len(targets), mode)
		for _, t := range targets {
			logs.Log.Infof("  %s", t)
		}
		logs.Log.Infof("Scanning...")
	}

	baseDir := targets[0]
	if opts.Input != "" {
		baseDir = opts.Input
	}
	writer := newOutputWriter(outputFormat, out, baseDir)
	var saveWriter *outputWriter
	if saveFile != nil {
		saveWriter = newOutputWriter(outputFormat, saveFile, baseDir)
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

	if len(opts.Expressions) > 0 {
		rule, err := buildExpressionRule(opts.Expressions, opts.ExtFilter, execOpts)
		if err != nil {
			return fmt.Errorf("invalid expression: %v", err)
		}
		inputs = append(inputs, rule)
	}

	scanner := file.NewScanner(inputs, execOpts)
	handleFinding := func(uf file.Finding) {
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
	}

	for _, target := range targets {
		scanner.Scan(target, handleFinding)
	}

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
			BaseDir:  baseDir,
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
		loaded := loadEmbeddedTemplates(&tmpls, opts.Categories, execOpts)
		if !loaded {
			for _, cat := range opts.Categories {
				catDir := filepath.Join(opts.TemplateDir, cat)
				if _, err := os.Stat(catDir); os.IsNotExist(err) {
					return nil, fmt.Errorf("category directory not found: %s (use -t to specify template path)", catDir)
				}
				loadFiltered(catDir)
			}
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
	return parseTemplate(path, data, execOpts)
}

func parseTemplate(name string, data []byte, execOpts *protocols.ExecuterOptions) (*templates.Template, error) {
	var tmpl templates.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse %s: %v", name, err)
	}
	if len(tmpl.RequestsFile) == 0 {
		return nil, fmt.Errorf("no file requests in %s", name)
	}
	if err := tmpl.Compile(execOpts); err != nil {
		return nil, fmt.Errorf("compile %s: %v", name, err)
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
	logs.Log.Console("Available templates:\n\n")

	if len(opts.Templates) > 0 {
		for _, path := range opts.Templates {
			info, err := os.Stat(path)
			if err != nil {
				logs.Log.Warnf("template not found: %s", path)
				continue
			}
			if !info.IsDir() {
				printTemplateInfoFromFile(path)
				continue
			}
			filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
					return nil
				}
				printTemplateInfoFromFile(p)
				return nil
			})
		}
		return nil
	}

	// List from embedded templates
	data := pkg.LoadConfig("found_keys")
	if len(data) > 0 {
		var pocs []interface{}
		if yaml.Unmarshal(data, &pocs) == nil {
			for _, poc := range pocs {
				bs, _ := yaml.Marshal(poc)
				printTemplateInfoFromData(bs)
			}
		}
		return nil
	}

	// Fallback to filesystem
	for _, cat := range opts.Categories {
		catDir := filepath.Join(opts.TemplateDir, cat)
		filepath.Walk(catDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
				return nil
			}
			printTemplateInfoFromFile(p)
			return nil
		})
	}
	return nil
}

func printTemplateInfoFromFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	printTemplateInfoFromData(data)
}

func printTemplateInfoFromData(data []byte) {
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

func buildExpressionRule(expressions []string, extFilter string, execOpts *protocols.ExecuterOptions) (file.Rule, error) {
	req := &file.Request{}

	if extFilter != "" {
		for _, ext := range strings.Split(extFilter, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				req.Extensions = append(req.Extensions, ext)
			}
		}
	} else {
		req.Extensions = []string{"all"}
	}

	var extractors []*operators.Extractor
	for _, expr := range expressions {
		extractors = append(extractors, &operators.Extractor{
			Type:  "regex",
			Regex: []string{expr},
		})
	}
	req.Extractors = extractors

	if err := req.Compile(execOpts); err != nil {
		return file.Rule{}, err
	}

	return file.Rule{
		ID:       "cli-expression",
		Name:     "CLI Expression",
		Severity: "info",
		Requests: []*file.Request{req},
	}, nil
}

// loadEmbeddedTemplates loads templates from the embedded pkg.LoadConfig data.
func loadEmbeddedTemplates(tmpls *[]*templates.Template, categories []string, execOpts *protocols.ExecuterOptions) bool {
	data := pkg.LoadConfig("found_keys")
	if len(data) == 0 {
		return false
	}
	var pocs []interface{}
	if err := yaml.Unmarshal(data, &pocs); err != nil {
		return false
	}
	for _, poc := range pocs {
		bs, err := yaml.Marshal(poc)
		if err != nil {
			continue
		}
		tmpl, err := parseTemplate("embedded", bs, execOpts)
		if err != nil {
			continue
		}
		*tmpls = append(*tmpls, tmpl)
	}
	return len(*tmpls) > 0
}

type autoProfile struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
		OS   string `yaml:"os"`
	} `yaml:"info"`
	Paths []string `yaml:"paths"`
}

// loadAutoTargets reads auto scan profiles from embedded templates and
// returns expanded, existing directory paths for the current OS.
func loadAutoTargets() []string {
	data := pkg.LoadConfig("found_auto")
	if len(data) == 0 {
		return nil
	}
	var profiles []autoProfile
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return nil
	}

	currentOS := runtime.GOOS
	var paths []string
	for _, p := range profiles {
		if p.Info.OS != currentOS {
			continue
		}
		for _, path := range p.Paths {
			expanded := expandPath(path)
			if expanded == "" {
				continue
			}
			if _, err := os.Stat(expanded); err == nil {
				paths = append(paths, expanded)
			}
		}
	}

	if len(paths) > 0 {
		logs.Log.Infof("Auto-detected %d targets for %s", len(paths), currentOS)
	}
	return paths
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, path[2:])
	}
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return home
	}
	return os.ExpandEnv(path)
}
