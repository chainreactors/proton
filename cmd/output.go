package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/protocols/file"
)

type Finding struct {
	TemplateID   string                    `json:"template-id"`
	TemplateName string                    `json:"template-name"`
	Severity     string                    `json:"severity"`
	FilePath     string                    `json:"file"`
	MatcherName  string                    `json:"matcher-name,omitempty"`
	Matches      map[string][]file.MatchEvent `json:"matches,omitempty"`
	Extracts     []file.MatchEvent         `json:"extracts,omitempty"`
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

	for name, events := range f.Matches {
		for _, ev := range events {
			val := ev.Value
			if len(val) > 200 {
				val = val[:200] + "..."
			}
			fmt.Fprintf(o.w, "   [%s] [L%d] %s\n", name, ev.Line, val)
		}
	}

	for _, ev := range f.Extracts {
		val := ev.Value
		if len(val) > 200 {
			val = val[:200] + "..."
		}
		fmt.Fprintf(o.w, "   [L%d] %s\n", ev.Line, val)
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

func printSummary(stats file.ScanStats, findingCount int, elapsed time.Duration, sevCount map[string]int) {
	logs.Log.Console(strings.Repeat("─", 60) + "\n")
	logs.Log.Consolef("Rules: %d | Files: %d (%s) | Time: %s | Findings: %d\n",
		stats.Rules, stats.Files, stats.HumanBytes(), elapsed.Round(time.Millisecond), findingCount)
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
