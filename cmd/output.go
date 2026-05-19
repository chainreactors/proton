package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/logs"
)

type Finding struct {
	TemplateID   string              `json:"template-id"`
	TemplateName string              `json:"template-name"`
	Severity     string              `json:"severity"`
	FilePath     string              `json:"file"`
	MatcherName  string              `json:"matcher-name,omitempty"`
	Matches      map[string][]string `json:"matches,omitempty"`
	Extracts     []string            `json:"extracts,omitempty"`
}

type outputWriter struct {
	format  string
	w       io.Writer
	baseDir string
}

func newOutputWriter(format string, w io.Writer, baseDir string) *outputWriter {
	return &outputWriter{format: format, w: w, baseDir: baseDir}
}

func (o *outputWriter) WriteFinding(f Finding) {
	if o.format == "json" {
		data, _ := json.Marshal(f)
		fmt.Fprintln(o.w, string(data))
		return
	}

	relPath := f.FilePath
	if r, err := filepath.Rel(o.baseDir, f.FilePath); err == nil {
		relPath = r
	}

	marker := severityMarker(f.Severity)
	if f.MatcherName != "" {
		fmt.Fprintf(o.w, "[%s] [%s] [%s] %s [%s]\n",
			f.TemplateName, marker, f.TemplateID, relPath, f.MatcherName)
	} else {
		fmt.Fprintf(o.w, "[%s] [%s] [%s] %s\n",
			f.TemplateName, marker, f.TemplateID, relPath)
	}

	printed := 0
	for name, vals := range f.Matches {
		for _, val := range vals {
			if len(val) > 120 {
				val = val[:120] + "..."
			}
			fmt.Fprintf(o.w, "   [%s] %s\n", name, val)
			printed++
			if printed >= 5 {
				break
			}
		}
		if printed >= 5 {
			total := 0
			for _, v := range f.Matches {
				total += len(v)
			}
			if total > 5 {
				fmt.Fprintf(o.w, "   ... +%d more matches\n", total-5)
			}
			break
		}
	}

	for i, e := range f.Extracts {
		if len(e) > 120 {
			e = e[:120] + "..."
		}
		fmt.Fprintf(o.w, "   %s\n", e)
		if i >= 4 {
			fmt.Fprintf(o.w, "   ... +%d more\n", len(f.Extracts)-5)
			break
		}
	}
	fmt.Fprintln(o.w)
}

func severityMarker(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info":
		return "info"
	default:
		return "unknown"
	}
}

func printSummary(tmplCount int, findingCount int, elapsed time.Duration, sevCount map[string]int) {
	logs.Log.Console(strings.Repeat("─", 60) + "\n")
	logs.Log.Consolef("Templates: %d | Time: %s | Findings: %d\n", tmplCount, elapsed.Round(time.Millisecond), findingCount)
	if len(sevCount) > 0 {
		var parts []string
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if c, ok := sevCount[s]; ok {
				parts = append(parts, fmt.Sprintf("%s=%d", s, c))
			}
		}
		logs.Log.Consolef("Severity: %s\n", strings.Join(parts, " "))
	}
}
