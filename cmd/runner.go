package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const Version = "v0.1.1"

const banner = `
   ____                  __
  / __/__  __ _____  ___/ /
 / _// _ \/ // / _ \/ _  /
/_/  \___/\_,_/_//_/\_,_/  ` + Version + "\n"

func init() {
	loadFiltersFromEmbedded()
}

func Run(opts *Options) error {
	if opts.UpdateTemplates {
		return runUpdateTemplates(opts)
	}
	if opts.Validate {
		return runValidate(opts)
	}
	if opts.Display != "" {
		return runTemplateDisplay(opts)
	}
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
	if len(targets) == 0 && opts.PID == 0 {
		return fmt.Errorf("target (-i), --auto, or --pid is required, run 'found --help' for usage")
	}

	var tmpls []*template.Template
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
		return fmt.Errorf("no templates loaded — use -t to specify templates, -c for categories, or -e for regex")
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

	useColor := isTTY(os.Stdout) && !opts.NoColor && outputFormat == "text"
	showProgress := isTTY(os.Stderr) && !opts.Quiet && outputFormat == "text"
	if useColor {
		logs.Log.SetColor(true)
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
	}

	var baseDir string
	if len(targets) > 0 {
		baseDir = targets[0]
	}
	if opts.Input != "" {
		baseDir = opts.Input
	}
	writer := newOutputWriter(outputFormat, out, baseDir, useColor)
	var saveWriter *outputWriter
	if saveFile != nil {
		saveWriter = newOutputWriter(outputFormat, saveFile, baseDir, false)
	}

	ignFilter := loadIgnoreFilter(targets, opts.IgnoreFiles)
	if ignFilter != nil && !opts.Quiet && outputFormat == "text" {
		logs.Log.Infof("Loaded %d ignore rules (post-scan suppression)", len(ignFilter.rules))
	}

	bl := loadBaseline(opts.Baseline)
	if bl != nil && len(bl.Entries) > 0 && !opts.Quiet && outputFormat == "text" {
		logs.Log.Infof("Loaded baseline with %d known findings", len(bl.Entries))
	}
	failOn := parseFailOn(opts.FailOn)

	sevFilter := parseSeverityFilter(opts.Severity)
	start := time.Now()
	var findingCount int
	var baselinedCount int
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

	stopProgress := func() {}
	if showProgress {
		stopProgress = startProgress(scanner)
	}

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

		relPath := f.FilePath
		if r, err := filepath.Rel(baseDir, f.FilePath); err == nil {
			relPath = r
		}
		if ignFilter.shouldIgnore(f.TemplateID, relPath) {
			return
		}
		if opts.Baseline != "" && isSamePath(f.FilePath, opts.Baseline, baseDir) {
			return
		}
		if opts.Findings != "" && isSamePath(f.FilePath, opts.Findings, baseDir) {
			return
		}

		if bl != nil {
			bkey := findingKey(f.TemplateID, relPath, f.Matches, f.Extracts)
			if bl.Contains(bkey) {
				baselinedCount++
				return
			}
		}

		findingCount++
		sevCount[f.Severity]++
		allFindings = append(allFindings, f)
		if outputFormat != "zombie" {
			if showProgress {
				fmt.Fprint(os.Stderr, "\r\033[K")
			}
			writer.WriteFinding(f)
			if saveWriter != nil {
				saveWriter.WriteFinding(f)
			}
		}
	}

	if opts.PID > 0 {
		memOpts := memoryScanOptions{ScanAll: opts.MemAll}
		if !opts.Quiet && outputFormat == "text" {
			logs.Log.Infof("Scanning process memory: PID %d", opts.PID)
		}
		if err := scanProcess(scanner, opts.PID, memOpts, handleFinding); err != nil {
			if len(targets) == 0 {
				return fmt.Errorf("memory scan failed: %v", err)
			}
			logs.Log.Warnf("memory scan: %v", err)
		}
	}

	for _, target := range targets {
		scanner.Scan(target, handleFinding)
	}

	stopProgress()
	elapsed := time.Since(start)
	if !opts.Quiet && outputFormat == "text" {
		suppressed := 0
		if ignFilter != nil {
			suppressed = ignFilter.suppressed
		}
		printSummary(scanner.Stats, findingCount, elapsed, sevCount, useColor, suppressed)
		if baselinedCount > 0 {
			printBaselineSummary(findingCount+baselinedCount, findingCount, baselinedCount, useColor)
		}
	}

	if saveFile != nil && !opts.Quiet {
		logs.Log.Infof("Results saved to %s", opts.SaveFile)
	}

	if opts.Findings != "" {
		b := createBaseline(allFindings, baseDir)
		if err := saveBaseline(b, opts.Findings); err != nil {
			return fmt.Errorf("save findings: %v", err)
		}
		if !opts.Quiet && outputFormat == "text" {
			logs.Log.Infof("Findings saved to %s (%d entries)", opts.Findings, len(b.Entries))
		}
	}

	if outputFormat == "zombie" {
		writeZombieOutput(out, allFindings, opts.Quiet)
		if saveFile != nil {
			writeZombieOutput(saveFile, allFindings, true)
		}
	}

	if opts.Collect != "" && len(allFindings) > 0 {
		copts := collectOpts{
			ZipPath:  opts.Collect,
			BaseDir:  baseDir,
			KeepTree: opts.CollectTree,
			Findings: allFindings,
		}
		if err := collectFiles(copts); err != nil {
			return fmt.Errorf("collect files: %v", err)
		}
	}

	if shouldFail(failOn, sevCount) {
		return &ExitError{Code: 1, Msg: "findings match --fail-on criteria"}
	}

	return nil
}

func loadTemplates(opts *Options) ([]*template.Template, error) {
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

	var tmpls []*template.Template

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
		tmplDir := resolveTemplateDir(opts)
		if loadLocalTemplates(&tmpls, tmplDir, opts.Categories, execOpts) {
			logs.Log.Debugf("Loaded templates from %s", tmplDir)
		} else if loaded := loadEmbeddedTemplates(&tmpls, opts.Categories, execOpts); !loaded {
			categoryDirs := categoryTemplateDirs(opts.TemplateDir, opts.Categories)
			loadedCategory := false
			for _, catDir := range categoryDirs {
				if _, err := os.Stat(catDir); os.IsNotExist(err) {
					continue
				}
				loadedCategory = true
				if err := loadFiltered(catDir); err != nil {
					return nil, fmt.Errorf("loading template category %s: %v", catDir, err)
				}
			}
			if !loadedCategory {
				return nil, fmt.Errorf("category directory not found: %s (use -t to specify template path)", strings.Join(categoryDirs, ", "))
			}
		}
	}

	tmpls = filterTemplates(tmpls, opts)
	return tmpls, nil
}

func loadFromPath(path string, execOpts *protocols.ExecuterOptions) ([]*template.Template, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		tmpl, err := loadSingleTemplate(path, execOpts)
		if err != nil {
			return nil, err
		}
		return []*template.Template{tmpl}, nil
	}

	var tmpls []*template.Template
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

func loadSingleTemplate(path string, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTemplate(path, data, execOpts)
}

func parseTemplate(name string, data []byte, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	var tmpl template.Template
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

func filterTemplates(tmpls []*template.Template, opts *Options) []*template.Template {
	includeTags := toSet(opts.Tags)
	excludeTags := toSet(opts.ExcludeTags)
	includeIDs := toSet(opts.TemplateIDs)
	excludeIDs := toSet(opts.ExcludeIDs)

	if len(includeTags) == 0 && len(excludeTags) == 0 &&
		len(includeIDs) == 0 && len(excludeIDs) == 0 {
		return tmpls
	}

	var filtered []*template.Template
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

type templateInfo struct {
	id       string
	name     string
	severity string
}

func listTemplates(opts *Options) error {
	var infos []templateInfo

	if len(opts.Templates) > 0 {
		for _, path := range opts.Templates {
			info, err := os.Stat(path)
			if err != nil {
				logs.Log.Warnf("template not found: %s", path)
				continue
			}
			if !info.IsDir() {
				if ti := getTemplateInfoFromFile(path); ti != nil {
					infos = append(infos, *ti)
				}
				continue
			}
			filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
					return nil
				}
				if ti := getTemplateInfoFromFile(p); ti != nil {
					infos = append(infos, *ti)
				}
				return nil
			})
		}
	} else if localInfos := listLocalTemplateInfos(resolveTemplateDir(opts)); len(localInfos) > 0 {
		infos = localInfos
	} else if appendEmbeddedTemplateInfos(&infos, opts.Categories) {
	} else {
		for _, catDir := range categoryTemplateDirs(opts.TemplateDir, opts.Categories) {
			filepath.Walk(catDir, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
					return nil
				}
				if ti := getTemplateInfoFromFile(p); ti != nil {
					infos = append(infos, *ti)
				}
				return nil
			})
		}
	}

	useColor := isTTY(os.Stdout) && !opts.NoColor
	logs.Log.Consolef("Available templates: %d\n\n", len(infos))

	groups := map[string][]templateInfo{}
	for _, ti := range infos {
		groups[ti.severity] = append(groups[ti.severity], ti)
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		list := groups[sev]
		if len(list) == 0 {
			continue
		}
		marker := severityMarker(sev, useColor)
		logs.Log.Consolef("  [%s] (%d)\n", marker, len(list))
		for _, t := range list {
			fmt.Printf("    %-35s %s\n", t.id, t.name)
		}
		logs.Log.Console("\n")
	}

	return nil
}

func getTemplateInfoFromFile(path string) *templateInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return getTemplateInfoFromData(data)
}

func getTemplateInfoFromData(data []byte) *templateInfo {
	var tmpl template.Template
	if yaml.Unmarshal(data, &tmpl) != nil {
		return nil
	}
	if len(tmpl.RequestsFile) == 0 {
		return nil
	}
	sev := tmpl.Info.Severity
	if sev == "" {
		sev = "unknown"
	}
	return &templateInfo{id: tmpl.Id, name: tmpl.Info.Name, severity: sev}
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

func embeddedTemplateConfigs(categories []string) []string {
	seen := make(map[string]bool)
	var configs []string
	for _, cat := range canonicalTemplateCategories(categories) {
		name := "found_" + strings.ReplaceAll(cat, "/", "_")
		if seen[name] {
			continue
		}
		seen[name] = true
		configs = append(configs, name)
	}
	return configs
}

func appendEmbeddedTemplateInfos(infos *[]templateInfo, categories []string) bool {
	loaded := false
	for _, config := range embeddedTemplateConfigs(categories) {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if yaml.Unmarshal(data, &pocs) != nil {
			continue
		}
		for _, poc := range pocs {
			bs, _ := yaml.Marshal(poc)
			if ti := getTemplateInfoFromData(bs); ti != nil {
				*infos = append(*infos, *ti)
				loaded = true
			}
		}
	}
	return loaded
}

// loadEmbeddedTemplates loads templates from the embedded pkg.LoadConfig data.
func loadEmbeddedTemplates(tmpls *[]*template.Template, categories []string, execOpts *protocols.ExecuterOptions) bool {
	loaded := false
	for _, config := range embeddedTemplateConfigs(categories) {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if err := yaml.Unmarshal(data, &pocs); err != nil {
			continue
		}
		for _, poc := range pocs {
			bs, err := yaml.Marshal(poc)
			if err != nil {
				continue
			}
			tmpl, err := parseTemplate("embedded:"+config, bs, execOpts)
			if err != nil {
				continue
			}
			*tmpls = append(*tmpls, tmpl)
			loaded = true
		}
	}
	return loaded
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
		for _, rawPath := range p.Paths {
			for _, expanded := range expandPaths(rawPath) {
				if _, err := os.Stat(expanded); err == nil {
					paths = append(paths, expanded)
				}
			}
		}
	}

	if len(paths) > 0 {
		logs.Log.Infof("Auto-detected %d targets for %s", len(paths), currentOS)
	}
	return paths
}

// expandPaths expands ~ and environment variables, then resolves globs.
func expandPaths(raw string) []string {
	// Expand ~ to home directory
	if strings.HasPrefix(raw, "~/") || strings.HasPrefix(raw, "~\\") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		raw = filepath.Join(home, raw[2:])
	} else if raw == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		raw = home
	}

	// Expand environment variables (%VAR% on Windows, $VAR on Unix)
	raw = os.ExpandEnv(raw)

	// If contains glob characters, expand
	if strings.ContainsAny(raw, "*?[") {
		matches, err := filepath.Glob(raw)
		if err != nil || len(matches) == 0 {
			return nil
		}
		return matches
	}

	return []string{raw}
}

// loadFiltersFromEmbedded loads extension and directory filters from embedded
// templates and applies them to the proton file scanner.
func loadFiltersFromEmbedded() {
	cfg := file.FilterConfig{}

	if extData := pkg.LoadConfig("found_filter_ext"); len(extData) > 0 {
		var extGroups map[string][]string
		if yaml.Unmarshal(extData, &extGroups) == nil {
			cfg.AlwaysDenyExts = toExtSet(extGroups["always"])
			cfg.ExecDenyExts = toExtSet(extGroups["executable"])
			cfg.ArchiveDenyExts = toExtSet(extGroups["archive"])
			cfg.DocDenyExts = toExtSet(extGroups["document"])
			cfg.MiscDenyExts = toExtSet(extGroups["misc"])
		}
	}

	if dirData := pkg.LoadConfig("found_filter_dir"); len(dirData) > 0 {
		var dirGroups map[string][]string
		if yaml.Unmarshal(dirData, &dirGroups) == nil {
			cfg.SkipDirs = toExtSet(dirGroups["skip"])
		}
	}

	file.SetFilters(cfg)
}

func startProgress(scanner *file.Scanner) func() {
	done := make(chan struct{})
	start := time.Now()
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				files := atomic.LoadInt64(&scanner.Stats.Files)
				regions := atomic.LoadInt64(&scanner.Stats.Regions)
				bytes := atomic.LoadInt64(&scanner.Stats.Bytes)
				findings := atomic.LoadInt64(&scanner.Stats.Findings)
				elapsed := time.Since(start).Round(100 * time.Millisecond)
				if regions > 0 && files > 0 {
					fmt.Fprintf(os.Stderr, "\r\033[K  Scanning: %d files + %d regions (%s) | %d findings | %s",
						files, regions, progressBytes(bytes), findings, elapsed)
				} else if regions > 0 {
					fmt.Fprintf(os.Stderr, "\r\033[K  Scanning: %d regions (%s) | %d findings | %s",
						regions, progressBytes(bytes), findings, elapsed)
				} else {
					fmt.Fprintf(os.Stderr, "\r\033[K  Scanning: %d files (%s) | %d findings | %s",
						files, progressBytes(bytes), findings, elapsed)
				}
			}
		}
	}()
	return func() {
		close(done)
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

func progressBytes(b int64) string {
	f := float64(b)
	switch {
	case f >= 1<<30:
		return fmt.Sprintf("%.1fGB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1fMB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.1fKB", f/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func toExtSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}
