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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const Version = "v0.1.1"

const Banner = `
   ____                  __
  / __/__  __ _____  ___/ /
 / _// _ \/ // / _ \/ _  /
/_/  \___/\_,_/_//_/\_,_/  ` + Version + "\n"

type Runner struct {
	Config    *Config
	Scanner   *file.Scanner
	templates []*template.Template

	// scan state — populated during Run()
	execOpts     *protocols.ExecuterOptions
	sysRules     []sysRule
	registryRules []sysRule
	writer       *outputWriter
	saveWriter   *outputWriter
	ignFilter    *ignoreFilter
	baseline     *Baseline
	failOn       map[string]bool
	sevFilter    map[string]bool

	outputFormat string
	baseDir      string
	useColor     bool
	showProgress bool
	startTime    time.Time

	seen          map[string]bool
	sevCount      map[string]int
	findingCount  int
	baselinedCount int
	allFindings   []Finding
}

func New(cfg *Config) (*Runner, error) {
	LoadFiltersFromEmbedded()

	var targets []string
	if cfg.Auto {
		targets = append(targets, loadAutoTargets()...)
	}
	if cfg.Input != "" {
		targets = append(targets, cfg.Input)
	}
	targets = append(targets, cfg.Targets...)
	targets = append(targets, expandScopeTargets(cfg)...)
	cfg.Targets = targets

	hasScope := cfg.ProcessScanEnabled() || cfg.RegistryScanEnabled() ||
		cfg.Keyring || cfg.Git || cfg.Clipboard || cfg.Keylog || cfg.Listen != ""

	var tmpls []*template.Template
	if len(cfg.Templates) > 0 || len(cfg.Expressions) == 0 {
		var err error
		tmpls, err = LoadTemplates(cfg)
		if err != nil {
			return nil, err
		}
	}
	if len(tmpls) == 0 && len(cfg.Expressions) == 0 {
		return nil, fmt.Errorf("no templates loaded — use -t to specify templates, -c for categories, or -e for regex")
	}
	if len(targets) == 0 && !hasScope && !templatesHaveRegistryRequests(tmpls) {
		return nil, fmt.Errorf("target (-i), --auto, --pid, --registry, or --listen is required")
	}

	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !cfg.Bin},
	}

	var inputs []file.Rule
	for _, tmpl := range tmpls {
		if len(tmpl.RequestsFile) > 0 {
			inputs = append(inputs, file.Rule{
				ID: tmpl.Id, Name: tmpl.Info.Name,
				Severity: tmpl.Info.Severity, Requests: tmpl.RequestsFile,
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

	return &Runner{
		Config:    cfg,
		Scanner:   file.NewScanner(inputs, execOpts),
		templates: tmpls,
		execOpts:  execOpts,
	}, nil
}

func (r *Runner) Run() error {
	r.initRunState()

	if err := r.printBanner(); err != nil {
		return err
	}

	stopProgress := r.startProgressIfNeeded()

	r.scanProcesses()
	r.scanRegistryAll()
	r.scanKeyring()
	r.scanGitHistory()
	r.scanFiles()
	r.runMonitors()

	stopProgress()
	return r.finalize()
}

// --- init ---

func (r *Runner) initRunState() {
	cfg := r.Config

	r.outputFormat = cfg.Output
	if cfg.JSON {
		r.outputFormat = "json"
	}
	r.useColor = IsTTY(os.Stdout) && !cfg.NoColor && r.outputFormat == "text"
	r.showProgress = IsTTY(os.Stderr) && !cfg.Quiet && r.outputFormat == "text"

	if r.useColor {
		logs.Log.SetColor(true)
	}

	if len(cfg.Targets) > 0 {
		r.baseDir = cfg.Targets[0]
	}

	r.startTime = time.Now()
	r.seen = make(map[string]bool)
	r.sevCount = make(map[string]int)
	r.sevFilter = parseSeverityFilter(cfg.Severity)
	r.failOn = parseFailOn(cfg.FailOn)
	r.ignFilter = loadIgnoreFilter(cfg.Targets, cfg.IgnoreFiles)
	r.baseline = loadBaseline(cfg.Baseline)

	r.buildSysRules()
}

func (r *Runner) buildSysRules() {
	for _, tmpl := range r.templates {
		for _, req := range tmpl.RequestsSys {
			rule := sysRule{
				ID: tmpl.Id, Name: tmpl.Info.Name,
				Severity: tmpl.Info.Severity, Request: req,
			}
			if req.Source == sysinfo.SourceRegistry {
				r.registryRules = append(r.registryRules, rule)
			} else {
				r.sysRules = append(r.sysRules, rule)
			}
		}
	}

	if r.Config.PID > 0 && len(r.Config.Expressions) > 0 {
		exprRule, err := buildExpressionRule(r.Config.Expressions, r.Config.ExtFilter, r.execOpts)
		if err == nil {
			for _, req := range exprRule.Requests {
				r.sysRules = append(r.sysRules, sysRule{
					ID: exprRule.ID, Name: exprRule.Name,
					Severity: exprRule.Severity, FileReq: req,
				})
			}
		}
	}
}

// --- banner ---

func (r *Runner) printBanner() error {
	cfg := r.Config

	if !cfg.Quiet && r.outputFormat == "text" {
		logs.Log.Console(Banner)
		mode := "TextOnly"
		if cfg.Bin {
			mode = "Binary: on"
		}
		logs.Log.Infof("Loaded %d rules | Targets: %d | %s", r.Scanner.Stats.Rules, len(cfg.Targets), mode)
		for _, t := range cfg.Targets {
			logs.Log.Infof("  %s", t)
		}
	}

	r.writer = newOutputWriter(r.outputFormat, os.Stdout, r.baseDir, r.useColor)

	if cfg.SaveFile != "" {
		f, err := os.Create(cfg.SaveFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %v", err)
		}
		r.saveWriter = newOutputWriter(r.outputFormat, f, r.baseDir, false)
	}

	if r.ignFilter != nil && !cfg.Quiet && r.outputFormat == "text" {
		logs.Log.Infof("Loaded %d ignore rules", len(r.ignFilter.rules))
	}
	if r.baseline != nil && len(r.baseline.Entries) > 0 && !cfg.Quiet && r.outputFormat == "text" {
		logs.Log.Infof("Loaded baseline with %d known findings", len(r.baseline.Entries))
	}

	return nil
}

// --- handleFinding ---

func (r *Runner) handleFinding(uf file.Finding) {
	cfg := r.Config

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

	if len(r.sevFilter) > 0 {
		if _, ok := r.sevFilter[f.Severity]; !ok {
			return
		}
	}

	key := f.TemplateID + "|" + f.FilePath
	if r.seen[key] {
		return
	}
	r.seen[key] = true

	relPath := f.FilePath
	if rel, err := filepath.Rel(r.baseDir, f.FilePath); err == nil {
		relPath = rel
	}
	if r.ignFilter.shouldIgnore(f.TemplateID, relPath) {
		return
	}
	if cfg.Baseline != "" && isSamePath(f.FilePath, cfg.Baseline, r.baseDir) {
		return
	}
	if cfg.Findings != "" && isSamePath(f.FilePath, cfg.Findings, r.baseDir) {
		return
	}

	if r.baseline != nil {
		bkey := findingKey(f.TemplateID, relPath, f.Matches, f.Extracts)
		if r.baseline.Contains(bkey) {
			r.baselinedCount++
			return
		}
	}

	r.findingCount++
	r.sevCount[f.Severity]++
	r.allFindings = append(r.allFindings, f)

	if r.outputFormat != "zombie" {
		if r.showProgress {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		r.writer.WriteFinding(f)
		if r.saveWriter != nil {
			r.saveWriter.WriteFinding(f)
		}
	}
}

// --- scan phases ---

func (r *Runner) scanProcesses() {
	cfg := r.Config
	if !cfg.ProcessScanEnabled() {
		return
	}

	pids, err := resolveTargetPIDs(cfg)
	if err != nil {
		logs.Log.Warnf("process enumeration: %v", err)
		return
	}
	r.logf("Scanning %d process(es)", len(pids))

	sources := cfg.ProcessSources()
	for _, pid := range pids {
		if len(sources) > 0 {
			scanProcessSources(r.Scanner, r.execOpts, pid, sources, r.handleFinding, cfg.Quiet, r.outputFormat)
		}
		if cfg.Mem || cfg.MemAll || (len(sources) == 0 && !cfg.Env && !cfg.Cmdline && !cfg.Fd && !cfg.Conn && !cfg.Pipe) {
			if len(r.sysRules) > 0 {
				if err := scanProcessWithSysRules(r.sysRules, r.execOpts, pid, r.handleFinding); err != nil {
					logs.Log.Warnf("pid %d memory: %v", pid, err)
				}
			} else {
				if err := scanProcess(r.Scanner, pid, cfg.MemAll, r.handleFinding); err != nil {
					logs.Log.Warnf("pid %d memory: %v", pid, err)
				}
			}
		}
	}
}

func (r *Runner) scanRegistryAll() {
	cfg := r.Config

	if cfg.RegistryScanEnabled() {
		if len(cfg.RegistryHives) > 0 {
			r.logf("Scanning Windows registry (%d hive file(s))", len(cfg.RegistryHives))
		} else {
			r.logf("Scanning Windows registry")
		}
		if err := scanRegistry(r.Scanner, defaultRegistryOptionsFromConfig(cfg), r.handleFinding); err != nil {
			logs.Log.Warnf("registry scan: %v", err)
		}
	}

	if len(r.registryRules) > 0 {
		r.logf("Scanning Windows registry with %d sys rule(s)", len(r.registryRules))
		if err := scanRegistryWithSysRules(r.registryRules, r.execOpts, r.handleFinding); err != nil {
			logs.Log.Warnf("registry sys scan: %v", err)
		}
	}
}

func (r *Runner) scanKeyring() {
	if !r.Config.Keyring {
		return
	}
	r.logf("Scanning kernel keyring")
	scanKeyring(r.Scanner, r.handleFinding)
}

func (r *Runner) scanGitHistory() {
	if !r.Config.Git {
		return
	}
	targets := r.Config.Targets
	if len(targets) == 0 {
		targets = []string{"."}
	}
	r.logf("Scanning git history for deleted secrets")
	scanGitHistory(r.Scanner, targets, r.handleFinding)
}

func (r *Runner) scanFiles() {
	for _, target := range r.Config.Targets {
		r.Scanner.Scan(target, r.handleFinding)
	}
}

func (r *Runner) runMonitors() {
	cfg := r.Config
	if cfg.Listen == "" && !cfg.Clipboard && !cfg.Keylog {
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	onData := func(data []byte, label string) {
		scanData(r.Scanner, data, label, r.handleFinding)
	}

	var wg sync.WaitGroup

	if cfg.Listen != "" {
		r.logf("Capturing traffic on interface: %s", cfg.Listen)
		if cfg.BPFFilter != "" {
			r.logf("BPF filter: %s", cfg.BPFFilter)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := scanNetwork(ctx, r.Scanner, networkOpts{Interface: cfg.Listen, BPFFilter: cfg.BPFFilter}, r.handleFinding); err != nil && !errors.Is(err, context.Canceled) {
				logs.Log.Warnf("network capture: %v", err)
			}
		}()
	}

	if cfg.Clipboard {
		r.logf("Monitoring clipboard")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sysinfo.WatchClipboard(ctx, onData); err != nil && !errors.Is(err, context.Canceled) {
				logs.Log.Warnf("clipboard: %v", err)
			}
		}()
	}

	if cfg.Keylog {
		r.logf("Monitoring keystrokes")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sysinfo.WatchKeystrokes(ctx, onData); err != nil && !errors.Is(err, context.Canceled) {
				logs.Log.Warnf("keylog: %v", err)
			}
		}()
	}

	wg.Wait()
}

// --- finalize ---

func (r *Runner) finalize() error {
	cfg := r.Config

	if !cfg.Quiet && r.outputFormat == "text" {
		suppressed := 0
		if r.ignFilter != nil {
			suppressed = r.ignFilter.suppressed
		}
		printSummary(r.Scanner.Stats, r.findingCount, time.Since(r.startTime), r.sevCount, r.useColor, suppressed)
		if r.baselinedCount > 0 {
			printBaselineSummary(r.findingCount+r.baselinedCount, r.findingCount, r.baselinedCount, r.useColor)
		}
	}

	if cfg.SaveFile != "" && !cfg.Quiet {
		logs.Log.Infof("Results saved to %s", cfg.SaveFile)
	}

	if cfg.Findings != "" {
		b := createBaseline(r.allFindings, r.baseDir)
		if err := saveBaseline(b, cfg.Findings); err != nil {
			return fmt.Errorf("save findings: %v", err)
		}
		if !cfg.Quiet && r.outputFormat == "text" {
			logs.Log.Infof("Findings saved to %s (%d entries)", cfg.Findings, len(b.Entries))
		}
	}

	if r.outputFormat == "zombie" {
		writeZombieOutput(os.Stdout, r.allFindings, cfg.Quiet)
	}

	if cfg.Collect != "" && len(r.allFindings) > 0 {
		if err := collectFiles(collectOpts{
			ZipPath: cfg.Collect, BaseDir: r.baseDir,
			KeepTree: cfg.CollectTree, Findings: r.allFindings,
		}); err != nil {
			return fmt.Errorf("collect files: %v", err)
		}
	}

	if shouldFail(r.failOn, r.sevCount) {
		return &ExitError{Code: 1, Msg: "findings match --fail-on criteria"}
	}

	return nil
}

// --- helpers ---

func (r *Runner) logf(format string, args ...interface{}) {
	if !r.Config.Quiet && r.outputFormat == "text" {
		logs.Log.Infof(format, args...)
	}
}

func (r *Runner) startProgressIfNeeded() func() {
	if !r.showProgress {
		return func() {}
	}
	return startProgress(r.Scanner)
}

func templatesHaveRegistryRequests(tmpls []*template.Template) bool {
	for _, tmpl := range tmpls {
		for _, req := range tmpl.RequestsSys {
			if req.Source == sysinfo.SourceRegistry {
				return true
			}
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

type autoProfile struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
		OS   string `yaml:"os"`
	} `yaml:"info"`
	Paths []string `yaml:"paths"`
}

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

func expandPaths(raw string) []string {
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
	raw = os.ExpandEnv(raw)
	if strings.ContainsAny(raw, "*?[") {
		matches, err := filepath.Glob(raw)
		if err != nil || len(matches) == 0 {
			return nil
		}
		return matches
	}
	return []string{raw}
}
