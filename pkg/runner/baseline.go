package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/proton/proton/file"
)

type Baseline struct {
	Version   string          `json:"version"`
	Generated string          `json:"generated"`
	Entries   []BaselineEntry `json:"entries"`
	index     map[string]bool
}

type BaselineEntry struct {
	Key        string `json:"key"`
	TemplateID string `json:"template-id"`
	File       string `json:"file"`
	Severity   string `json:"severity"`
	Digest     string `json:"digest"`
}

func findingKey(templateID, relPath string, matches map[string][]file.MatchEvent, extracts []file.MatchEvent) string {
	h := sha256.New()
	h.Write([]byte(templateID))
	h.Write([]byte{0})
	h.Write([]byte(relPath))
	h.Write([]byte{0})

	var parts []string
	for _, events := range matches {
		for _, ev := range events {
			parts = append(parts, ev.Value)
		}
	}
	for _, ev := range extracts {
		parts = append(parts, ev.Value)
	}
	sort.Strings(parts)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

func loadBaseline(path string) *Baseline {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logs.Log.Warnf("baseline file not found: %s (treating as empty)", path)
		return &Baseline{index: map[string]bool{}}
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		logs.Log.Warnf("invalid baseline file: %v (treating as empty)", err)
		return &Baseline{index: map[string]bool{}}
	}
	b.index = make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		b.index[e.Key] = true
	}
	return &b
}

func (b *Baseline) Contains(key string) bool {
	if b == nil || b.index == nil {
		return false
	}
	return b.index[key]
}

func createBaseline(findings []Finding, baseDir string) *Baseline {
	b := &Baseline{
		Version:   "1",
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range findings {
		relPath := f.FilePath
		if r, err := filepath.Rel(baseDir, f.FilePath); err == nil {
			relPath = r
		}
		key := findingKey(f.TemplateID, relPath, f.Matches, f.Extracts)

		digest := ""
		var parts []string
		for _, events := range f.Matches {
			for _, ev := range events {
				parts = append(parts, ev.Value)
			}
		}
		for _, ev := range f.Extracts {
			parts = append(parts, ev.Value)
		}
		if len(parts) > 0 {
			digest = parts[0]
			if len(digest) > 60 {
				digest = digest[:60] + "..."
			}
		}

		b.Entries = append(b.Entries, BaselineEntry{
			Key:        key,
			TemplateID: f.TemplateID,
			File:       relPath,
			Severity:   f.Severity,
			Digest:     digest,
		})
	}
	return b
}

func saveBaseline(b *Baseline, path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func parseFailOn(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, sev := range strings.Split(s, ",") {
		m[strings.TrimSpace(strings.ToLower(sev))] = true
	}
	return m
}

func shouldFail(failOn map[string]bool, sevCount map[string]int) bool {
	if failOn == nil {
		return false
	}
	for sev := range failOn {
		if sevCount[sev] > 0 {
			return true
		}
	}
	return false
}

func printBaselineSummary(total, newFindings, baselined int, useColor bool) {
	if baselined > 0 {
		logs.Log.Consolef("Baseline: %d known (suppressed), %d new\n", baselined, newFindings)
	}
}

func printCreateBaselineSummary(path string, count int) {
	logs.Log.Infof("Baseline created: %s (%d entries)", path, count)
	logs.Log.Infof("Commit this file to your repository to track known findings")
}

func isSamePath(filePath, baselinePath, baseDir string) bool {
	absBaseline, err := filepath.Abs(baselinePath)
	if err != nil {
		return false
	}
	absFile := filePath
	if !filepath.IsAbs(filePath) {
		absFile = filepath.Join(baseDir, filePath)
	}
	return absFile == absBaseline
}

// ExitError is returned when --fail-on triggers
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s", e.Msg)
}
