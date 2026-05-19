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
	TemplateID   string   `json:"template_id"`
	TemplateName string   `json:"template_name"`
	Severity     string   `json:"severity"`
	FilePath     string   `json:"file"`
	Matched      string   `json:"matched,omitempty"`
	Extracts     []string `json:"extracts,omitempty"`
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
	sev := strings.ToUpper(f.Severity)
	marker := severityMarker(f.Severity)
	fmt.Fprintf(o.w, "[%s] %s (%s)\n", marker, f.TemplateID, f.TemplateName)
	fmt.Fprintf(o.w, "       File: %s\n", relPath)
	for i, e := range f.Extracts {
		if len(e) > 120 {
			e = e[:120] + "..."
		}
		fmt.Fprintf(o.w, "       Match: %s\n", e)
		if i >= 2 {
			fmt.Fprintf(o.w, "       ... +%d more\n", len(f.Extracts)-3)
			break
		}
	}
	_ = sev
	fmt.Fprintln(o.w)
}

func severityMarker(s string) string {
	switch s {
	case "critical":
		return "CRT"
	case "high":
		return "HIG"
	case "medium":
		return "MED"
	case "low":
		return "LOW"
	case "info":
		return "INF"
	default:
		return "UNK"
	}
}

func printBanner(w io.Writer) {
	fmt.Fprint(w, banner)
}

func printSummary(w io.Writer, tmplCount int, findingCount int, elapsed time.Duration, sevCount map[string]int) {
	fmt.Fprintln(w, strings.Repeat("─", 50))
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
