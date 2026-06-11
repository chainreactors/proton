package runner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const (
	sourceDir = "/mnt/chainreactors"
	tmplDir   = "/mnt/chainreactors/proton/templates/found/keys"
)

type benchTemplates struct {
	tmpls   []*template.Template
	rules   []file.Rule
	regexps []*regexp.Regexp
}

var (
	tmplOnce sync.Once
	tmplData *benchTemplates
)

func getTemplates(tb testing.TB) *benchTemplates {
	tb.Helper()
	tmplOnce.Do(func() {
		tmplData = loadAllTemplates()
	})
	if tmplData == nil || len(tmplData.tmpls) == 0 {
		tb.Skip("no templates found")
	}
	return tmplData
}

func loadAllTemplates() *benchTemplates {
	t := &benchTemplates{}
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
	filepath.Walk(tmplDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var tmpl template.Template
		if yaml.Unmarshal(data, &tmpl) != nil || len(tmpl.RequestsFile) == 0 {
			return nil
		}
		if tmpl.Compile(execOpts) != nil {
			return nil
		}
		t.tmpls = append(t.tmpls, &tmpl)
		return nil
	})
	for _, tmpl := range t.tmpls {
		t.rules = append(t.rules, file.Rule{
			ID: tmpl.Id, Name: tmpl.Info.Name, Severity: tmpl.Info.Severity,
			Requests: tmpl.RequestsFile,
		})
	}
	for _, tmpl := range t.tmpls {
		for _, req := range tmpl.RequestsFile {
			if req.CompiledOperators != nil {
				for _, ext := range req.CompiledOperators.Extractors {
					for _, p := range ext.Regex {
						if re, e := regexp.Compile(p); e == nil {
							t.regexps = append(t.regexps, re)
						}
					}
				}
				for _, m := range req.CompiledOperators.Matchers {
					for _, p := range m.Regex {
						if re, e := regexp.Compile(p); e == nil {
							t.regexps = append(t.regexps, re)
						}
					}
				}
			}
		}
	}
	return t
}

// collectBenchFiles walks sourceDir and collects text files up to sizeLimit bytes.
func collectBenchFiles(sizeLimit int64) ([]string, int64) {
	var files []string
	var total int64
	filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go", ".py", ".js", ".ts", ".yaml", ".yml", ".json", ".md",
			".txt", ".conf", ".toml", ".sh", ".html", ".css", ".xml",
			".sql", ".env", ".pem", ".key", ".cfg", ".ini", ".rs",
			".c", ".cpp", ".h", ".java", ".rb", ".php", ".lua",
			".swift", ".kt", ".proto", ".jsx", ".tsx", ".vue",
			".properties", ".tf", ".hcl", ".mod", ".sum":
		default:
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() == 0 || info.Size() > 10<<20 {
			return nil
		}
		if total+info.Size() > sizeLimit {
			return fs.SkipAll
		}
		files = append(files, path)
		total += info.Size()
		return nil
	})
	return files, total
}

func stageSymlinks(tb testing.TB, files []string) string {
	tb.Helper()
	dir := tb.TempDir()
	for i, path := range files {
		ext := filepath.Ext(path)
		os.Symlink(path, filepath.Join(dir, fmt.Sprintf("%06d%s", i, ext)))
	}
	return dir
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	}
}

// TestBenchmarkTiers runs proton and naive at 1KB, 1MB, 1GB with all templates
// and prints a comparison table.
func TestBenchmarkTiers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := os.Stat(sourceDir); err != nil {
		t.Skipf("source dir %s not available: %v", sourceDir, err)
	}
	tmpl := getTemplates(t)
	t.Logf("templates: %d (%d regex patterns)", len(tmpl.tmpls), len(tmpl.regexps))

	tiers := []struct {
		name  string
		limit int64
	}{
		{"1 KB", 1 << 10},
		{"1 MB", 1 << 20},
		{"1 GB", 1 << 30},
	}

	type result struct {
		name        string
		files       int
		dataSize    int64
		protonTime  time.Duration
		naiveTime   time.Duration
		naiveActual bool // true if directly measured, false if projected
	}

	var results []result

	for _, tier := range tiers {
		files, totalSize := collectBenchFiles(tier.limit)
		if len(files) == 0 {
			t.Logf("%s: no files found, skipping", tier.name)
			continue
		}
		t.Logf("%s: %d files, %s", tier.name, len(files), humanBytes(totalSize))

		// proton
		stageDir := stageSymlinks(t, files)
		execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
		scanner := file.NewScanner(tmpl.rules, execOpts)

		start := time.Now()
		scanner.Scan(stageDir, func(fd file.Finding) {})
		protonDur := time.Since(start)

		// naive: directly measure up to 1MB, project beyond
		naiveSampleLimit := totalSize
		if naiveSampleLimit > 1<<20 {
			naiveSampleLimit = 1 << 20
		}
		var sampleFiles []string
		var sampleSize int64
		for _, path := range files {
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			sampleFiles = append(sampleFiles, path)
			sampleSize += info.Size()
			if sampleSize >= naiveSampleLimit {
				break
			}
		}

		start = time.Now()
		for _, path := range sampleFiles {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			body := string(data)
			for _, re := range tmpl.regexps {
				re.FindAllString(body, -1)
			}
		}
		naiveSampleDur := time.Since(start)

		var naiveDur time.Duration
		actual := true
		if sampleSize < totalSize {
			naiveDur = time.Duration(float64(naiveSampleDur) * float64(totalSize) / float64(sampleSize))
			actual = false
		} else {
			naiveDur = naiveSampleDur
		}

		results = append(results, result{
			name: tier.name, files: len(files), dataSize: totalSize,
			protonTime: protonDur, naiveTime: naiveDur, naiveActual: actual,
		})
	}

	t.Logf("")
	t.Logf("=== proton vs naive regex — %d templates, %d patterns ===", len(tmpl.tmpls), len(tmpl.regexps))
	t.Logf("")
	t.Logf("  %-8s %-18s %-15s %-20s %-10s", "Tier", "Files", "proton", "naive", "Speedup")
	t.Logf("  %-8s %-18s %-15s %-20s %-10s", "────────", "──────────────────", "───────────────", "────────────────────", "──────────")
	for _, r := range results {
		naiveStr := r.naiveTime.Round(time.Millisecond).String()
		if !r.naiveActual {
			naiveStr = "~" + naiveStr + " (proj.)"
		}
		speedup := float64(r.naiveTime) / float64(r.protonTime)
		t.Logf("  %-8s %-18s %-15s %-20s %.0fx",
			r.name,
			fmt.Sprintf("%d × %s", r.files, humanBytes(r.dataSize)),
			r.protonTime.Round(time.Microsecond),
			naiveStr,
			speedup,
		)
	}
}
