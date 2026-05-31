package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

const testTemplateValid = `id: test-secret-key
info:
  name: Test Secret Key
  severity: high
  tags: test,secret
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "SECRET_KEY=[a-zA-Z0-9]{16}"
`

const testTemplateValid2 = `id: test-db-password
info:
  name: Test DB Password
  severity: medium
  tags: test,database
file:
  - extensions:
      - .env
    extractors:
      - type: regex
        regex:
          - "DB_PASSWORD=[^\n]+"
`

const testTemplateMissingID = `info:
  name: Missing ID Template
  severity: high
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "test"
`

const testTemplateBadRegex = `id: bad-regex-template
info:
  name: Bad Regex
  severity: high
  tags: test
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "[invalid(regex"
`

const testTemplateBadSeverity = `id: bad-severity
info:
  name: Bad Severity
  severity: unknown
  tags: test
file:
  - extensions:
      - all
    extractors:
      - type: regex
        regex:
          - "test123"
`

func setupTestTemplateDir(t *testing.T, templates map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range templates {
		path := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(path), 0755)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func setupTestTarget(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(path), 0755)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadTemplatesFromDirectory(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml":        testTemplateValid,
		"subdir/rule2.yaml": testTemplateValid2,
	})

	opts := &Options{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Bin = false

	tmpls, err := loadTemplates(opts)
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}
	if len(tmpls) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(tmpls))
	}

	ids := map[string]bool{}
	for _, tmpl := range tmpls {
		ids[tmpl.Id] = true
	}
	if !ids["test-secret-key"] {
		t.Error("missing template test-secret-key")
	}
	if !ids["test-db-password"] {
		t.Error("missing template test-db-password")
	}
}

func TestLoadTemplatesFromSingleFile(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})

	opts := &Options{}
	opts.Templates = []string{filepath.Join(tmplDir, "rule1.yaml")}
	opts.Categories = []string{"keys"}

	tmpls, err := loadTemplates(opts)
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}
	if len(tmpls) != 1 {
		t.Fatalf("expected 1 template, got %d", len(tmpls))
	}
	if tmpls[0].Id != "test-secret-key" {
		t.Errorf("expected id test-secret-key, got %s", tmpls[0].Id)
	}
}

func TestLoadTemplatesMultiplePaths(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"a/rule1.yaml": testTemplateValid,
		"b/rule2.yaml": testTemplateValid2,
	})

	opts := &Options{}
	opts.Templates = []string{
		filepath.Join(tmplDir, "a"),
		filepath.Join(tmplDir, "b"),
	}
	opts.Categories = []string{"keys"}

	tmpls, err := loadTemplates(opts)
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}
	if len(tmpls) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(tmpls))
	}
}

func TestLoadLocalTemplatesWithCategories(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"keys/rule1.yaml":   testTemplateValid,
		"custom/rule2.yaml": testTemplateValid2,
	})

	opts := &Options{}
	opts.Categories = []string{"keys"}
	opts.UpdateTemplateDir = tmplDir

	tmpls, err := loadTemplates(opts)
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}
	if len(tmpls) != 1 {
		t.Fatalf("expected 1 template (only keys category), got %d", len(tmpls))
	}
	if tmpls[0].Id != "test-secret-key" {
		t.Errorf("expected test-secret-key, got %s", tmpls[0].Id)
	}
}

func TestLoadLocalTemplatesFallbackWalkAll(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml":        testTemplateValid,
		"subdir/rule2.yaml": testTemplateValid2,
	})

	opts := &Options{}
	opts.Categories = []string{"keys"}
	opts.UpdateTemplateDir = tmplDir

	tmpls, err := loadTemplates(opts)
	if err != nil {
		t.Fatalf("loadTemplates failed: %v", err)
	}
	if len(tmpls) != 2 {
		t.Fatalf("expected 2 templates (fallback walk all), got %d", len(tmpls))
	}
}

func TestValidateValidTemplates(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
		"rule2.yaml": testTemplateValid2,
	})

	results := validatePath(tmplDir)
	for _, r := range results {
		if !r.valid {
			t.Errorf("template %s should be valid, errors: %v", r.path, r.errors)
		}
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestValidateMissingID(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"bad.yaml": testTemplateMissingID,
	})

	results := validatePath(tmplDir)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].valid {
		t.Error("template with missing ID should be invalid")
	}
	found := false
	for _, e := range results[0].errors {
		if e == "missing required field \"id\"" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'missing required field id' error, got: %v", results[0].errors)
	}
}

func TestValidateBadRegex(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"bad.yaml": testTemplateBadRegex,
	})

	results := validatePath(tmplDir)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].valid {
		t.Error("template with bad regex should be invalid")
	}
	found := false
	for _, e := range results[0].errors {
		if len(e) > 0 && (contains(e, "compile") || contains(e, "regex")) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected compile/regex error, got: %v", results[0].errors)
	}
}

func TestValidateBadSeverity(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"bad.yaml": testTemplateBadSeverity,
	})

	results := validatePath(tmplDir)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].valid {
		t.Error("template with bad severity should be invalid")
	}
	found := false
	for _, e := range results[0].errors {
		if contains(e, "invalid severity") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'invalid severity' error, got: %v", results[0].errors)
	}
}

func TestValidateIDPattern(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"aws-access-key", true},
		{"test_rule_1", true},
		{"simple", true},
		{"CamelCase", true},
		{"has spaces", false},
		{"has.dots", false},
		{"special@char", false},
		{"-leading-dash", false},
	}

	for _, tt := range tests {
		got := validIDPattern.MatchString(tt.id)
		if got != tt.valid {
			t.Errorf("validIDPattern.MatchString(%q) = %v, want %v", tt.id, got, tt.valid)
		}
	}
}

func TestScanWithTemplateDir(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})
	targetDir := setupTestTarget(t, map[string]string{
		"app.conf": "SECRET_KEY=abcdefgh12345678\n",
		"clean.txt": "nothing here\n",
	})

	opts := &Options{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Input = targetDir
	opts.Output = "json"
	opts.Quiet = true

	err := Run(opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

func TestTemplateDisplayByPath(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})

	opts := &Options{}
	opts.Display = filepath.Join(tmplDir, "rule1.yaml")
	opts.Quiet = true

	err := Run(opts)
	if err != nil {
		t.Fatalf("template display by path failed: %v", err)
	}
}

func TestTemplateDisplayNotFound(t *testing.T) {
	opts := &Options{}
	opts.Display = "nonexistent-template-id-xyz"
	opts.Quiet = true
	opts.UpdateTemplateDir = t.TempDir()

	err := Run(opts)
	if err == nil {
		t.Fatal("expected error for nonexistent template")
	}
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfg := &FoundConfig{
		TemplateURL: "git@github.com:test/templates.git",
		TemplateDir: "/custom/path",
	}
	if err := saveFoundConfig(cfg); err != nil {
		t.Fatalf("saveFoundConfig failed: %v", err)
	}

	loaded := loadFoundConfig()
	if loaded.TemplateURL != cfg.TemplateURL {
		t.Errorf("TemplateURL = %q, want %q", loaded.TemplateURL, cfg.TemplateURL)
	}
	if loaded.TemplateDir != cfg.TemplateDir {
		t.Errorf("TemplateDir = %q, want %q", loaded.TemplateDir, cfg.TemplateDir)
	}
}

func TestResolveTemplateDirPriority(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfg := &FoundConfig{TemplateDir: "/from-config"}
	saveFoundConfig(cfg)

	opts := &Options{}
	opts.UpdateTemplateDir = "/from-flag"
	if got := resolveTemplateDir(opts); got != "/from-flag" {
		t.Errorf("flag should win, got %q", got)
	}

	opts.UpdateTemplateDir = ""
	if got := resolveTemplateDir(opts); got != "/from-config" {
		t.Errorf("config should win over default, got %q", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
