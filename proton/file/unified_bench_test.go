//go:build go1.18
// +build go1.18

package file

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

func createBenchFiles(b *testing.B, dir string, count, sizeBytes int, matchRate float64) {
	b.Helper()
	var sb strings.Builder

	filler := "func processData(input []byte) ([]byte, error) { return input, nil }\n"
	secret := "password = hunter2_secret_value\n"

	for i := 0; i < count; i++ {
		sb.Reset()
		sb.Grow(sizeBytes + 256)
		lineNum := 0
		for sb.Len() < sizeBytes {
			if matchRate > 0 && float64(lineNum%100)/100.0 < matchRate {
				sb.WriteString(secret)
			} else {
				sb.WriteString(filler)
			}
			lineNum++
		}
		name := filepath.Join(dir, fmt.Sprintf("file_%05d.txt", i))
		if err := os.WriteFile(name, []byte(sb.String()[:sizeBytes]), 0644); err != nil {
			b.Fatal(err)
		}
	}
}

func makeBenchRules(count int) []Rule {
	rules := make([]Rule, count)
	baseWords := []string{"password", "secret_key", "api_token", "private_key", "access_key"}
	for i := 0; i < count; i++ {
		word := baseWords[i%len(baseWords)]
		req := &Request{
			ID:         fmt.Sprintf("bench-rule-%d", i),
			MaxSize:    "1Gb",
			Extensions: []string{"all"},
			Operators: operators.Operators{
				Matchers: []*operators.Matcher{{
					Part: "raw", Type: "word", Words: []string{word},
				}},
				Extractors: []*operators.Extractor{{
					Part:       "raw",
					Type:       "regex",
					Regex:      []string{fmt.Sprintf(`%s\s*=\s*(\S+)`, word)},
					RegexGroup: 1,
				}},
			},
		}
		opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
		if err := req.Compile(opts); err != nil {
			panic(err)
		}
		rules[i] = Rule{
			ID:       req.ID,
			Name:     fmt.Sprintf("Bench Rule %d", i),
			Severity: "info",
			Requests: []*Request{req},
		}
	}
	return rules
}

func BenchmarkScanner_SmallFiles(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 1000, 1024, 0.01)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		b.ReportMetric(float64(1000)/b.Elapsed().Seconds(), "files/sec")
	}
}

func BenchmarkScanner_LargeFiles(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 100*1024, 0.01)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
	}
}

func BenchmarkScanner_ManyTemplates(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 10*1024, 0.01)
	rules := makeBenchRules(50)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
	}
}

func BenchmarkScanner_LowMatchRate(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 1000, 1024, 0)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
	}
}

func BenchmarkScanner_HighMatchRate(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 10*1024, 0.5)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
	}
}

func BenchmarkProcessFile(b *testing.B) {
	for _, tc := range []struct {
		name      string
		sizeBytes int
		matchRate float64
		rules     int
	}{
		{"1KB_5rules", 1024, 0.05, 5},
		{"100KB_5rules", 100 * 1024, 0.01, 5},
		{"1KB_50rules", 1024, 0.05, 50},
		{"100KB_50rules", 100 * 1024, 0.01, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			dir := b.TempDir()
			createBenchFiles(b, dir, 1, tc.sizeBytes, tc.matchRate)
			filePath := filepath.Join(dir, "file_00000.txt")
			rules := makeBenchRules(tc.rules)
			opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
			scanner := NewScanner(rules, opts)
			group := scanner.Groups[0]

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = scanner.ProcessFile(filePath, group)
			}
		})
	}
}

func makeNaiveRegexps(count int) []*regexp.Regexp {
	baseWords := []string{"password", "secret_key", "api_token", "private_key", "access_key"}
	res := make([]*regexp.Regexp, count)
	for i := 0; i < count; i++ {
		word := baseWords[i%len(baseWords)]
		res[i] = regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*(\S+)`, word))
	}
	return res
}

func BenchmarkNaiveFile(b *testing.B) {
	for _, tc := range []struct {
		name      string
		sizeBytes int
		matchRate float64
		rules     int
	}{
		{"1KB_5rules", 1024, 0.05, 5},
		{"100KB_5rules", 100 * 1024, 0.01, 5},
		{"1KB_50rules", 1024, 0.05, 50},
		{"100KB_50rules", 100 * 1024, 0.01, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			dir := b.TempDir()
			createBenchFiles(b, dir, 1, tc.sizeBytes, tc.matchRate)
			filePath := filepath.Join(dir, "file_00000.txt")
			regexps := makeNaiveRegexps(tc.rules)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				data, _ := os.ReadFile(filePath)
				body := string(data)
				for _, re := range regexps {
					re.FindAllStringSubmatch(body, -1)
				}
			}
		})
	}
}

func BenchmarkLineLoop_StringConversion(b *testing.B) {
	line := []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz 1234", 3))

	b.Run("Unconditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s := string(line)
			_ = s
		}
	})

	b.Run("Lazy", func(b *testing.B) {
		b.ReportAllocs()
		needConvert := false
		for i := 0; i < b.N; i++ {
			var s string
			if needConvert {
				s = string(line)
			}
			_ = s
		}
	})
}

func BenchmarkFileResult_SliceAlloc(b *testing.B) {
	templateCount := 50
	matcherCount := 3
	extractorCount := 2

	b.Run("AllocPerFile", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			results := make([]fileResult, templateCount)
			for j := range results {
				results[j].matcherHits = make([][]matchHit, matcherCount)
				results[j].extractorHits = make([][]matchHit, extractorCount)
			}
			_ = results
		}
	})
}

func BenchmarkCompileRE2Patterns(b *testing.B) {
	patterns := []string{
		`password\s*=\s*\S+`,
		`secret_key\s*=\s*\S+`,
		`api_token\s*=\s*\S+`,
		`private_key\s*=\s*\S+`,
		`access_key\s*=\s*\S+`,
	}
	for _, p := range patterns {
		getOrCompileRE2(p)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getOrCompileRE2Slice(&patterns)
	}
}
