package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const Version = "v0.1.1"

const Banner = `
   ____                  __
  / __/__  __ _____  ___/ /
 / _// _ \/ // / _ \/ _  /
/_/  \___/\_,_/_//_/\_,_/  ` + Version + "\n"

// Runner encapsulates the scan orchestration logic.
type Runner struct {
	Config    *Config
	Scanner   *file.Scanner
	templates []*template.Template
	stats     file.ScanStats
}

// New creates a Runner from the given Config.
func New(cfg *Config) (*Runner, error) {
	LoadFiltersFromEmbedded()

	var targets []string
	if cfg.Auto {
		autoTargets := loadAutoTargets()
		targets = append(targets, autoTargets...)
	}
	if cfg.Input != "" {
		targets = append(targets, cfg.Input)
	}
	if len(cfg.Targets) > 0 {
		targets = append(targets, cfg.Targets...)
	}
	targets = append(targets, expandScopeTargets(cfg)...)
	cfg.Targets = targets

	hasScope := cfg.ProcessScanEnabled() || cfg.Keyring || cfg.Git || cfg.Listen != ""
	if len(targets) == 0 && !hasScope {
		return nil, fmt.Errorf("target (-i), --auto, --pid, or --listen is required, run 'found --help' for usage")
	}

	var tmpls []*template.Template
	hasExplicitTemplates := len(cfg.Templates) > 0
	expressionMode := len(cfg.Expressions) > 0
	if hasExplicitTemplates || !expressionMode {
		var err error
		tmpls, err = LoadTemplates(cfg)
		if err != nil {
			return nil, err
		}
	}
	if len(tmpls) == 0 && len(cfg.Expressions) == 0 {
		return nil, fmt.Errorf("no templates loaded — use -t to specify templates, -c for categories, or -e for regex")
	}

	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !cfg.Bin},
	}
	var inputs []file.Rule
	for _, tmpl := range tmpls {
		if len(tmpl.RequestsFile) > 0 {
			inputs = append(inputs, file.Rule{
				ID:       tmpl.Id,
				Name:     tmpl.Info.Name,
				Severity: tmpl.Info.Severity,
				Requests: tmpl.RequestsFile,
			})
		}
	}

	if len(cfg.Expressions) > 0 {
		rule, err := buildExpressionRule(cfg.Expressions, cfg.ExtFilter, execOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid expression: %v", err)
		}
		inputs = append(inputs, rule)
	}

	scanner := file.NewScanner(inputs, execOpts)

	return &Runner{
		Config:    cfg,
		Scanner:   scanner,
		templates: tmpls,
	}, nil
}

// Run executes the scan and returns an error (possibly *ExitError) on failure.
func (r *Runner) Run() error {
	cfg := r.Config
	scanner := r.Scanner

	out := os.Stdout
	var saveFile *os.File
	if cfg.SaveFile != "" {
		f, err := os.Create(cfg.SaveFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %v", err)
		}
		defer f.Close()
		saveFile = f
	}

	outputFormat := cfg.Output
	if cfg.JSON {
		outputFormat = "json"
	}

	useColor := IsTTY(os.Stdout) && !cfg.NoColor && outputFormat == "text"
	showProgress := IsTTY(os.Stderr) && !cfg.Quiet && outputFormat == "text"
	if useColor {
		logs.Log.SetColor(true)
	}

	if !cfg.Quiet && outputFormat == "text" {
		logs.Log.Console(Banner)
		mode := "TextOnly"
		if cfg.Bin {
			mode = "Binary: on"
		}
		logs.Log.Infof("Loaded %d rules | Targets: %d | %s", scanner.Stats.Rules, len(cfg.Targets), mode)
		for _, t := range cfg.Targets {
			logs.Log.Infof("  %s", t)
		}
	}

	var baseDir string
	if len(cfg.Targets) > 0 {
		baseDir = cfg.Targets[0]
	}
	writer := newOutputWriter(outputFormat, out, baseDir, useColor)
	var saveWriter *outputWriter
	if saveFile != nil {
		saveWriter = newOutputWriter(outputFormat, saveFile, baseDir, false)
	}

	ignFilter := loadIgnoreFilter(cfg.Targets, cfg.IgnoreFiles)
	if ignFilter != nil && !cfg.Quiet && outputFormat == "text" {
		logs.Log.Infof("Loaded %d ignore rules (post-scan suppression)", len(ignFilter.rules))
	}

	bl := loadBaseline(cfg.Baseline)
	if bl != nil && len(bl.Entries) > 0 && !cfg.Quiet && outputFormat == "text" {
		logs.Log.Infof("Loaded baseline with %d known findings", len(bl.Entries))
	}
	failOn := parseFailOn(cfg.FailOn)

	sevFilter := parseSeverityFilter(cfg.Severity)
	start := time.Now()
	var findingCount int
	var baselinedCount int
	sevCount := map[string]int{}
	seen := map[string]bool{}
	var allFindings []Finding

	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !cfg.Bin},
	}
	var sysRules []sysRule
	for _, tmpl := range r.templates {
		for _, req := range tmpl.RequestsSys {
			sysRules = append(sysRules, sysRule{
				ID:       tmpl.Id,
				Name:     tmpl.Info.Name,
				Severity: tmpl.Info.Severity,
				Request:  req,
			})
		}
	}

	// For --pid with -e (expression mode), also add expressions to mem scanner
	if cfg.PID > 0 && len(cfg.Expressions) > 0 {
		exprRule, err := buildExpressionRule(cfg.Expressions, cfg.ExtFilter, execOpts)
		if err == nil {
			for _, req := range exprRule.Requests {
				sysRules = append(sysRules, sysRule{
					ID:       exprRule.ID,
					Name:     exprRule.Name,
					Severity: exprRule.Severity,
					FileReq:  req,
				})
			}
		}
	}

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
		if cfg.Baseline != "" && isSamePath(f.FilePath, cfg.Baseline, baseDir) {
			return
		}
		if cfg.Findings != "" && isSamePath(f.FilePath, cfg.Findings, baseDir) {
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

	if cfg.ProcessScanEnabled() {
		pids, err := resolveTargetPIDs(cfg)
		if err != nil {
			return fmt.Errorf("process enumeration: %v", err)
		}
		if !cfg.Quiet && outputFormat == "text" {
			logs.Log.Infof("Scanning %d process(es)", len(pids))
		}
		sources := cfg.ProcessSources()
		for _, pid := range pids {
			if len(sources) > 0 {
				scanProcessSources(scanner, execOpts, pid, sources, handleFinding, cfg.Quiet, outputFormat)
			}
			if cfg.Mem || cfg.MemAll || (len(sources) == 0 && !cfg.Env && !cfg.Cmdline && !cfg.Fd && !cfg.Conn && !cfg.Pipe) {
				if len(sysRules) > 0 {
					if err := scanProcessWithSysRules(sysRules, execOpts, pid, handleFinding); err != nil {
						logs.Log.Warnf("pid %d memory: %v", pid, err)
					}
				} else {
					if err := scanProcess(scanner, pid, cfg.MemAll, handleFinding); err != nil {
						logs.Log.Warnf("pid %d memory: %v", pid, err)
					}
				}
			}
		}
	}

	if cfg.Listen != "" {
		netOpts := networkOpts{Interface: cfg.Listen, BPFFilter: cfg.BPFFilter}
		if !cfg.Quiet && outputFormat == "text" {
			logs.Log.Infof("Capturing traffic on interface: %s", cfg.Listen)
			if cfg.BPFFilter != "" {
				logs.Log.Infof("BPF filter: %s", cfg.BPFFilter)
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := scanNetwork(ctx, scanner, netOpts, handleFinding); err != nil {
			if !errors.Is(err, context.Canceled) {
				if len(cfg.Targets) == 0 && !cfg.ProcessScanEnabled() {
					return fmt.Errorf("network capture failed: %v", err)
				}
				logs.Log.Warnf("network capture: %v", err)
			}
		}
	}

	if cfg.Keyring {
		if !cfg.Quiet && outputFormat == "text" {
			logs.Log.Infof("Scanning kernel keyring")
		}
		scanKeyring(scanner, handleFinding)
	}

	if cfg.Git {
		gitTargets := cfg.Targets
		if len(gitTargets) == 0 {
			gitTargets = []string{"."}
		}
		if !cfg.Quiet && outputFormat == "text" {
			logs.Log.Infof("Scanning git history for deleted secrets")
		}
		scanGitHistory(scanner, gitTargets, handleFinding)
	}

	for _, target := range cfg.Targets {
		scanner.Scan(target, handleFinding)
	}

	stopProgress()
	elapsed := time.Since(start)
	if !cfg.Quiet && outputFormat == "text" {
		suppressed := 0
		if ignFilter != nil {
			suppressed = ignFilter.suppressed
		}
		printSummary(scanner.Stats, findingCount, elapsed, sevCount, useColor, suppressed)
		if baselinedCount > 0 {
			printBaselineSummary(findingCount+baselinedCount, findingCount, baselinedCount, useColor)
		}
	}

	if saveFile != nil && !cfg.Quiet {
		logs.Log.Infof("Results saved to %s", cfg.SaveFile)
	}

	if cfg.Findings != "" {
		b := createBaseline(allFindings, baseDir)
		if err := saveBaseline(b, cfg.Findings); err != nil {
			return fmt.Errorf("save findings: %v", err)
		}
		if !cfg.Quiet && outputFormat == "text" {
			logs.Log.Infof("Findings saved to %s (%d entries)", cfg.Findings, len(b.Entries))
		}
	}

	if outputFormat == "zombie" {
		writeZombieOutput(out, allFindings, cfg.Quiet)
		if saveFile != nil {
			writeZombieOutput(saveFile, allFindings, true)
		}
	}

	if cfg.Collect != "" && len(allFindings) > 0 {
		copts := collectOpts{
			ZipPath:  cfg.Collect,
			BaseDir:  baseDir,
			KeepTree: cfg.CollectTree,
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
				packets := atomic.LoadInt64(&scanner.Stats.Packets)
				bytes := atomic.LoadInt64(&scanner.Stats.Bytes)
				findings := atomic.LoadInt64(&scanner.Stats.Findings)
				elapsed := time.Since(start).Round(100 * time.Millisecond)
				if packets > 0 {
					fmt.Fprintf(os.Stderr, "\r\033[K  Capturing: %d packets (%s) | %d findings | %s",
						packets, progressBytes(bytes), findings, elapsed)
				} else if regions > 0 && files > 0 {
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
