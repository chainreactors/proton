package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/proton/file"
)

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

type Finding struct {
	TemplateID   string                       `json:"template-id"`
	TemplateName string                       `json:"template-name"`
	Severity     string                       `json:"severity"`
	FilePath     string                       `json:"file"`
	MatcherName  string                       `json:"matcher-name,omitempty"`
	Matches      map[string][]file.MatchEvent `json:"matches,omitempty"`
	Extracts     []file.MatchEvent            `json:"extracts,omitempty"`
}

type outputWriter struct {
	format  string
	w       io.Writer
	baseDir string
	color   bool
}

func newOutputWriter(format string, w io.Writer, baseDir string, color bool) *outputWriter {
	return &outputWriter{format: format, w: w, baseDir: baseDir, color: color}
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

	marker := severityMarker(f.Severity, o.color)
	name := o.applyColor(f.TemplateName, logs.Green)
	tid := o.applyColor(f.TemplateID, logs.Cyan)
	if f.MatcherName != "" {
		mname := o.applyColor(f.MatcherName, logs.Purple)
		fmt.Fprintf(o.w, "[%s] [%s] [%s] %s [%s]\n",
			name, marker, tid, relPath, mname)
	} else {
		fmt.Fprintf(o.w, "[%s] [%s] [%s] %s\n",
			name, marker, tid, relPath)
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

func (o *outputWriter) applyColor(s string, fn func(string) string) string {
	if o.color {
		return fn(s)
	}
	return s
}

func severityMarker(s string, color bool) string {
	if !color {
		return s
	}
	switch s {
	case "critical":
		return logs.RedBold(s)
	case "high":
		return logs.Red(s)
	case "medium":
		return logs.Yellow(s)
	case "low":
		return logs.Cyan(s)
	case "info":
		return logs.Blue(s)
	default:
		return s
	}
}

func printSummary(stats file.ScanStats, findingCount int, elapsed time.Duration, sevCount map[string]int, color bool, suppressed int) {
	logs.Log.Console(strings.Repeat("─", 60) + "\n")
	logs.Log.Consolef("Rules: %d | Files: %d (%s) | Time: %s | Findings: %d\n",
		stats.Rules, stats.Files, stats.HumanBytes(), elapsed.Round(time.Millisecond), findingCount)
	if findingCount == 0 && suppressed == 0 {
		logs.Log.Console("No findings detected.\n")
		return
	}
	if len(sevCount) > 0 {
		var parts []string
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if c, ok := sevCount[s]; ok {
				part := fmt.Sprintf("%s=%d", s, c)
				if color && c > 0 {
					part = severityMarker(part, true)
				}
				parts = append(parts, part)
			}
		}
		logs.Log.Consolef("Severity: %s\n", strings.Join(parts, " "))
	}
	if suppressed > 0 {
		logs.Log.Consolef("Suppressed: %d (by ignore rules)\n", suppressed)
	}
}
