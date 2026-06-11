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

// TestExecute_MultiLineExtractMerge 验证跨行的多条提取结果正确合并到 opResult
func TestExecute_MultiLineExtractMerge(t *testing.T) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "multi.txt"), []byte(
		"SECRET_A=aaaaaaaaaaaaaaaa1234\nSECRET_B=bbbbbbbbbbbbbbbb5678\nAKIAIOSFODNN7EXAMPLE\n",
	), 0644)

	result, err := tmpl.Execute(filepath.Join(dir, "multi.txt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OutputExtracts) < 3 {
		t.Fatalf("expected at least 3 extracts from 3 lines, got %d: %v", len(result.OutputExtracts), result.OutputExtracts)
	}
}

// TestExecute_Directory 验证 Execute 传入目录时能递归扫描
func TestExecute_Directory(t *testing.T) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("SECRET_X=zzzzzzzzzzzzzzzz9999\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here\n"), 0644)

	result, err := tmpl.Execute(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Extracted {
		t.Fatal("directory scan should extract secrets")
	}
	if len(result.OutputExtracts) < 2 {
		t.Fatalf("expected at least 2 extracts from dir, got %d: %v", len(result.OutputExtracts), result.OutputExtracts)
	}
}

// TestExecute_Glob 验证 Execute 传入 glob 模式
func TestExecute_Glob(t *testing.T) {
	var tmpl Template
	yaml.Unmarshal([]byte(benchTmplYAML), &tmpl)
	if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.conf"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.log"), []byte("nothing\n"), 0644)

	result, err := tmpl.Execute(filepath.Join(dir, "*.conf"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Extracted {
		t.Fatal("glob scan should find secrets in .conf files")
	}
}

// TestExecute_ExtensionFilter 验证模板定义的扩展名过滤生效
func TestExecute_ExtensionFilter(t *testing.T) {
	const extTmpl = `
id: ext-filter
info:
  name: Extension Filter Test
  severity: info
file:
  - extensions:
      - .yaml
      - .yml
    matchers:
      - type: word
        words:
          - "secret"
`
	var tmpl Template
	yaml.Unmarshal([]byte(extTmpl), &tmpl)
	if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("secret: token\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("secret: token\n"), 0644)

	result, err := tmpl.Execute(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("should match .yaml file")
	}

	// 单独扫 .json 应该不匹配（扩展名不在 extensions 列表中）
	resultJSON, err := tmpl.Execute(filepath.Join(dir, "config.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resultJSON.Matched {
		t.Fatal(".json file should NOT match when extensions is [.yaml, .yml]")
	}
}

// TestExecute_DenyList 验证 denylist 生效
func TestExecute_DenyList(t *testing.T) {
	const denyTmpl = `
id: deny-test
info:
  name: Denylist Test
  severity: info
file:
  - extensions:
      - all
    denylist:
      - .log
    matchers:
      - type: word
        words:
          - "secret"
`
	var tmpl Template
	yaml.Unmarshal([]byte(denyTmpl), &tmpl)
	if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.conf"), []byte("secret=value\n"), 0644)
	os.WriteFile(filepath.Join(dir, "app.log"), []byte("secret=value\n"), 0644)

	result, err := tmpl.Execute(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("should match .conf file")
	}
}
