package template

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"gopkg.in/yaml.v3"
)

const benchTmplYAML = `
id: bench-secrets
info:
  name: Bench Secrets
  severity: high
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "SECRET_[A-Z0-9_]+=[a-zA-Z0-9/+]{16,}"
          - "AKIA[A-Z0-9]{16}"
          - "(?i)password\\s*[=:]\\s*\\S+"
          - "-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
          - "(?i)(?:api[_-]?key|token|secret)\\s*[=:]\\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
`

func setupBenchDir(b *testing.B, numFiles, linesPerFile int) string {
	b.Helper()
	dir := b.TempDir()
	for i := 0; i < numFiles; i++ {
		var content []byte
		for j := 0; j < linesPerFile; j++ {
			if j == linesPerFile/2 {
				content = append(content, []byte("SECRET_DB_PASS=abcdefghijklmnop1234\n")...)
			} else if j == linesPerFile/3 {
				content = append(content, []byte("AKIAIOSFODNN7EXAMPLE\n")...)
			} else {
				content = append(content, []byte(fmt.Sprintf("config_line_%d = value_%d\n", j, j))...)
			}
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%03d.conf", i)), content, 0644)
	}
	return dir
}

func BenchmarkTemplateExecute(b *testing.B) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
	tmpl.Compile(execOpts)

	dir := setupBenchDir(b, 10, 100)

	files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			tmpl.Execute(f, nil)
		}
	}
}

func BenchmarkTemplateScanData(b *testing.B) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
	tmpl.Compile(execOpts)

	data := []byte("SECRET_DB_PASS=abcdefghijklmnop1234\nAKIAIOSFODNN7EXAMPLE\nclean line\n")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tmpl.ScanData(data, "bench:mem")
	}
}

func TestExecuteCorrectness(t *testing.T) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
	if err := tmpl.Compile(execOpts); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte(
		"SECRET_DB_PASS=abcdefghijklmnop1234\nAKIAIOSFODNN7EXAMPLE\nclean line\n",
	), 0644)

	result, err := tmpl.Execute(filepath.Join(dir, "test.txt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Extracted {
		t.Fatal("should extract secrets")
	}
	if len(result.OutputExtracts) < 2 {
		t.Fatalf("expected at least 2 extracts, got %d: %v", len(result.OutputExtracts), result.OutputExtracts)
	}

	// ScanData
	findings := tmpl.ScanData([]byte("AKIAIOSFODNN7EXAMPLE\n"), "test:mem")
	if len(findings) == 0 {
		t.Fatal("ScanData should find AKIA key")
	}
}
