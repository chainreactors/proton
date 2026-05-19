package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const banner = `
   ____                  __
  / __/__  __ _____  ___/ /
 / _// _ \/ // / _ \/ _  /
/_/  \___/\_,_/_//_/\_,_/  v0.1.0
`

type Finding struct {
	TemplateID   string            `json:"template-id"`
	TemplateName string            `json:"template-name"`
	Severity     string            `json:"severity"`
	FilePath     string            `json:"file"`
	MatcherName  string            `json:"matcher-name,omitempty"`
	MatchedAt    string            `json:"matched-at,omitempty"`
	Matches      map[string]string `json:"matches,omitempty"`
	Extracts     []string          `json:"extracts,omitempty"`
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

	for name, val := range f.Matches {
		if len(val) > 120 {
			val = val[:120] + "..."
		}
		fmt.Fprintf(o.w, "   [%s] %s\n", name, val)
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

func printBanner(w io.Writer) {
	fmt.Fprint(w, banner)
}

func printSummary(w io.Writer, tmplCount int, findingCount int, elapsed time.Duration, sevCount map[string]int) {
	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintf(w, "Templates: %d | Time: %s | Findings: %d\n", tmplCount, elapsed.Round(time.Millisecond), findingCount)
	if len(sevCount) > 0 {
		fmt.Fprint(w, "Severity: ")
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if c, ok := sevCount[s]; ok {
				fmt.Fprintf(w, "%s=%d ", s, c)
			}
		}
		fmt.Fprintln(w)
	}
}
