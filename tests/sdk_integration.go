//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg/runner"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const testTemplate = `
id: sdk-test-secrets
info:
  name: SDK Test
  severity: high
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "SECRET_[A-Z0-9_]+=[a-zA-Z0-9/+]{8,}"
          - "AKIA[A-Z0-9]{16}"
`

var testData = "config=true\nSECRET_DB_PASS=abcdefghijk12345\nAKIAIOSFODNN7EXAMPLE\nclean line\n"

func main() {
	errors := 0
	check := func(name string, ok bool, msg string) {
		if ok {
			fmt.Printf("  PASS  %s\n", name)
		} else {
			fmt.Printf("  FAIL  %s: %s\n", name, msg)
			errors++
		}
	}

	// --- Setup ---
	dir, _ := os.MkdirTemp("", "sdk-test-*")
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "secrets.conf"), []byte(testData), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing\n"), 0644)

	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}

	// ============================================================
	fmt.Println("\n=== 1. Scanner atomic API (ScanData) ===")
	// ============================================================
	var tmpl template.Template
	yaml.Unmarshal([]byte(testTemplate), &tmpl)
	tmpl.Compile(execOpts)

	scanner := file.NewScanner([]file.Rule{{
		ID: "test", Name: "Test", Severity: "high",
		Requests: tmpl.RequestsFile,
	}}, execOpts)

	var scanDataFindings []file.Finding
	for _, group := range scanner.Groups {
		scanDataFindings = append(scanDataFindings, scanner.ScanData([]byte(testData), "test:mem", group)...)
	}
	check("ScanData finds secrets", len(scanDataFindings) > 0,
		fmt.Sprintf("got %d findings", len(scanDataFindings)))

	foundAKIA := false
	for _, f := range scanDataFindings {
		for _, e := range f.Extracts {
			if strings.Contains(e.Value, "AKIA") {
				foundAKIA = true
			}
		}
	}
	check("ScanData extracts AKIA key", foundAKIA, "AKIA not found in extracts")

	// ============================================================
	fmt.Println("\n=== 2. Scanner atomic API (ScanBlock) ===")
	// ============================================================
	blockData := make([]byte, 1024)
	copy(blockData[500:], []byte("SECRET_MEM_KEY=abcdefghijk12345"))
	var blockFindings []file.Finding
	for _, group := range scanner.Groups {
		blockFindings = append(blockFindings, scanner.ScanBlock(blockData, "test:block", group)...)
	}
	check("ScanBlock finds in binary", len(blockFindings) > 0,
		fmt.Sprintf("got %d findings", len(blockFindings)))

	// ============================================================
	fmt.Println("\n=== 3. Scanner streaming API (LineWriter) ===")
	// ============================================================
	var lineFindings []file.Finding
	lw := scanner.NewLineWriter("test:stream", func(f file.Finding) {
		lineFindings = append(lineFindings, f)
	})
	lw.Write([]byte("line1=ok\nSECRET_STREAM_"))
	lw.Write([]byte("TOKEN=abcdefghijk12345\nline3\n"))
	lw.Close()
	check("LineWriter finds across chunks", len(lineFindings) > 0,
		fmt.Sprintf("got %d findings", len(lineFindings)))

	// ============================================================
	fmt.Println("\n=== 4. Scanner streaming API (BlockWriter) ===")
	// ============================================================
	var bwFindings []file.Finding
	bw := scanner.NewBlockWriter("test:blockstream", func(f file.Finding) {
		bwFindings = append(bwFindings, f)
	})
	chunk := make([]byte, 256)
	copy(chunk[100:], []byte("AKIAIOSFODNN7EXAMPLE"))
	bw.Write(chunk)
	bw.Close()
	check("BlockWriter finds in binary stream", len(bwFindings) > 0,
		fmt.Sprintf("got %d findings", len(bwFindings)))

	// ============================================================
	fmt.Println("\n=== 5. Scanner file reading (ReadFile) ===")
	// ============================================================
	var readFindings []file.Finding
	for _, group := range scanner.Groups {
		contents := scanner.ReadFile(filepath.Join(dir, "secrets.conf"), group)
		check("ReadFile returns content", len(contents) > 0,
			fmt.Sprintf("got %d contents", len(contents)))
		for _, c := range contents {
			readFindings = append(readFindings, scanner.ScanData(c.Data, c.Label, group)...)
		}
	}
	check("ReadFile+ScanData finds secrets", len(readFindings) > 0,
		fmt.Sprintf("got %d findings", len(readFindings)))

	// ============================================================
	fmt.Println("\n=== 6. Template.Execute (single-template convenience) ===")
	// ============================================================
	result, err := tmpl.Execute(filepath.Join(dir, "secrets.conf"), nil)
	check("Execute no error", err == nil, fmt.Sprintf("%v", err))
	check("Execute extracts secrets", result != nil && result.Extracted,
		fmt.Sprintf("result=%+v", result))
	check("Execute outputs >=2 values", result != nil && len(result.OutputExtracts) >= 2,
		fmt.Sprintf("outputs=%v", result.OutputExtracts))

	// ============================================================
	fmt.Println("\n=== 7. Template.ScanData (single-template in-memory) ===")
	// ============================================================
	tmplFindings := tmpl.ScanData([]byte(testData), "tmpl:direct")
	check("Template.ScanData finds secrets", len(tmplFindings) > 0,
		fmt.Sprintf("got %d", len(tmplFindings)))

	// ============================================================
	fmt.Println("\n=== 8. Runner programmatic API ===")
	// ============================================================
	cfg := &runner.Config{
		Input:      dir,
		Templates:  []string{},
		Categories: []string{"keys"},
		Expressions: []string{`AKIA[A-Z0-9]{16}`},
		Output:     "json",
		Quiet:      true,
	}
	r, err := runner.New(cfg)
	check("Runner.New no error", err == nil, fmt.Sprintf("%v", err))
	if err == nil {
		err = r.Run()
		check("Runner.Run no error", err == nil, fmt.Sprintf("%v", err))
	}

	// ============================================================
	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", 15-errors, errors)
	if errors > 0 {
		os.Exit(1)
	}
}
