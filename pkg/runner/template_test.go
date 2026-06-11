package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/template"
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
  severity: bogus
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

	opts := &Config{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Bin = false

	tmpls, err := LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
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

	opts := &Config{}
	opts.Templates = []string{filepath.Join(tmplDir, "rule1.yaml")}
	opts.Categories = []string{"keys"}

	tmpls, err := LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
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

	opts := &Config{}
	opts.Templates = []string{
		filepath.Join(tmplDir, "a"),
		filepath.Join(tmplDir, "b"),
	}
	opts.Categories = []string{"keys"}

	tmpls, err := LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
	}
	if len(tmpls) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(tmpls))
	}
}

func TestLoadLocalTemplatesWithCategories(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"found/keys/rule1.yaml":   testTemplateValid,
		"found/custom/rule2.yaml": testTemplateValid2,
	})

	opts := &Config{}
	opts.Categories = []string{"keys"}
	opts.TemplateDir = tmplDir

	tmpls, err := LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
	}
	if len(tmpls) != 1 {
		t.Fatalf("expected 1 template (only keys category), got %d", len(tmpls))
	}
	if tmpls[0].Id != "test-secret-key" {
		t.Errorf("expected test-secret-key, got %s", tmpls[0].Id)
	}
}

func TestLoadLocalTemplatesWithFoundCategoryLayout(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"found/keys/rule1.yaml":  testTemplateValid,
		"found/spray/rule2.yaml": testTemplateValid2,
	})

	opts := &Config{}
	opts.Categories = []string{"keys"}
	opts.TemplateDir = tmplDir

	tmpls, err := LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates keys failed: %v", err)
	}
	if len(tmpls) != 1 || tmpls[0].Id != "test-secret-key" {
		t.Fatalf("expected only keys template, got %d", len(tmpls))
	}

	opts.Categories = []string{"spray"}
	tmpls, err = LoadTemplates(opts)
	if err != nil {
		t.Fatalf("LoadTemplates spray failed: %v", err)
	}
	if len(tmpls) != 1 || tmpls[0].Id != "test-db-password" {
		t.Fatalf("expected only spray template, got %d", len(tmpls))
	}
}

func TestLoadLocalTemplatesRequiresFoundCategoryLayout(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"keys/rule1.yaml": testTemplateValid,
		"rule2.yaml":      testTemplateValid2,
	})

	dirs := categoryTemplateDirs(tmplDir, []string{"keys"})
	if len(dirs) != 1 || dirs[0] != filepath.Join(tmplDir, "found", "keys") {
		t.Fatalf("expected only found/keys category dir, got %#v", dirs)
	}

	var tmpls []*template.Template
	loaded := loadLocalTemplates(&tmpls, tmplDir, []string{"keys"}, &protocols.ExecuterOptions{Options: &protocols.Options{}})
	if loaded || len(tmpls) != 0 {
		t.Fatalf("expected no templates from non-found category layout, got %d", len(tmpls))
	}
}

func runConfig(cfg *Config) error {
	r, err := New(cfg)
	if err != nil {
		return err
	}
	return r.Run()
}

func TestScanWithTemplateDir(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})
	targetDir := setupTestTarget(t, map[string]string{
		"app.conf":  "SECRET_KEY=abcdefgh12345678\n",
		"clean.txt": "nothing here\n",
	})

	opts := &Config{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Input = targetDir
	opts.Output = "json"
	opts.Quiet = true

	err := runConfig(opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

func TestBaselineCreateAndFilter(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})
	targetDir := setupTestTarget(t, map[string]string{
		"app.conf":    "SECRET_KEY=abcdefgh12345678\n",
		"config.conf": "SECRET_KEY=zzzzzzzzzzzzzzzz\n",
	})

	opts := &Config{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Input = targetDir
	opts.Output = "json"
	opts.Quiet = true
	opts.Findings = filepath.Join(t.TempDir(), "baseline.json")

	if err := runConfig(opts); err != nil {
		t.Fatalf("Run with create-baseline failed: %v", err)
	}

	data, err := os.ReadFile(opts.Findings)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if len(bl.Entries) != 2 {
		t.Fatalf("expected 2 baseline entries, got %d", len(bl.Entries))
	}

	// Now scan again with baseline — should suppress both
	opts2 := &Config{}
	opts2.Templates = []string{tmplDir}
	opts2.Categories = []string{"keys"}
	opts2.Input = targetDir
	opts2.Output = "json"
	opts2.Quiet = true
	opts2.Baseline = opts.Findings

	if err := runConfig(opts2); err != nil {
		t.Fatalf("Run with baseline failed: %v", err)
	}
}

func TestFailOn(t *testing.T) {
	tmplDir := setupTestTemplateDir(t, map[string]string{
		"rule1.yaml": testTemplateValid,
	})
	targetDir := setupTestTarget(t, map[string]string{
		"app.conf": "SECRET_KEY=abcdefgh12345678\n",
	})

	opts := &Config{}
	opts.Templates = []string{tmplDir}
	opts.Categories = []string{"keys"}
	opts.Input = targetDir
	opts.Output = "json"
	opts.Quiet = true
	opts.FailOn = "high"

	err := runConfig(opts)
	if err == nil {
		t.Fatal("expected error from --fail-on high")
	}
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.Code)
	}

	// No match — should not fail
	opts.FailOn = "critical"
	if err := runConfig(opts); err != nil {
		t.Fatalf("should not fail on critical when only high findings: %v", err)
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

func TestZombieParseURL(t *testing.T) {
	tests := []struct {
		input   string
		wantIP  string
		wantSvc string
		wantUsr string
	}{
		{"mongodb://admin:pass@10.0.0.1:27017/db", "10.0.0.1", "mongo", "admin"},
		{"redis://cache:6379", "cache", "redis", ""},
		{"mysql://root:toor@db.local:3306/app", "db.local", "mysql", "root"},
		{"ssh://deploy@10.0.0.5:22", "10.0.0.5", "ssh", "deploy"},
		{"http://admin:secret@intranet:8080/api", "intranet", "http", "admin"},
		{"not-a-url", "", "", ""},
		{"", "", "", ""},
	}
	for _, tt := range tests {
		got := parseExtractValue(tt.input)
		if tt.wantIP == "" {
			if got != nil {
				t.Errorf("parseExtractValue(%q) = %+v, want nil", tt.input, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parseExtractValue(%q) = nil, want ip=%s", tt.input, tt.wantIP)
			continue
		}
		if got.IP != tt.wantIP {
			t.Errorf("parseExtractValue(%q).IP = %q, want %q", tt.input, got.IP, tt.wantIP)
		}
		if got.Service != tt.wantSvc {
			t.Errorf("parseExtractValue(%q).Service = %q, want %q", tt.input, got.Service, tt.wantSvc)
		}
		if got.Username != tt.wantUsr {
			t.Errorf("parseExtractValue(%q).Username = %q, want %q", tt.input, got.Username, tt.wantUsr)
		}
	}
}

func TestZombieParseJDBC(t *testing.T) {
	tests := []struct {
		input    string
		wantIP   string
		wantPort string
		wantUsr  string
		wantPass string
	}{
		{"jdbc:mysql://user:pass@10.0.0.1:3306/db", "10.0.0.1", "3306", "user", "pass"},
		{"jdbc:postgresql://host:5432/db;user=app;password=s3cret", "host", "5432", "app", "s3cret"},
		// oracle thin format requires special handling - skip in V1
	}
	for _, tt := range tests {
		got := parseExtractValue(tt.input)
		if got == nil {
			t.Errorf("parseExtractValue(%q) = nil", tt.input)
			continue
		}
		if got.IP != tt.wantIP {
			t.Errorf("%q: IP = %q, want %q", tt.input, got.IP, tt.wantIP)
		}
		if got.Port != tt.wantPort {
			t.Errorf("%q: Port = %q, want %q", tt.input, got.Port, tt.wantPort)
		}
		if got.Username != tt.wantUsr {
			t.Errorf("%q: Username = %q, want %q", tt.input, got.Username, tt.wantUsr)
		}
		if got.Password != tt.wantPass {
			t.Errorf("%q: Password = %q, want %q", tt.input, got.Password, tt.wantPass)
		}
	}
}

func TestZombieParseODBC(t *testing.T) {
	input := "Server=10.0.0.50;Port=1433;User Id=sa;Password=Str0ng;Database=master"
	got := parseExtractValue(input)
	if got == nil {
		t.Fatal("parseExtractValue(ODBC) = nil")
	}
	if got.IP != "10.0.0.50" {
		t.Errorf("IP = %q, want 10.0.0.50", got.IP)
	}
	if got.Port != "1433" {
		t.Errorf("Port = %q, want 1433", got.Port)
	}
	if got.Username != "sa" {
		t.Errorf("Username = %q, want sa", got.Username)
	}
	if got.Password != "Str0ng" {
		t.Errorf("Password = %q, want Str0ng", got.Password)
	}
}

func TestZombieFilterPlaceholders(t *testing.T) {
	got := parseExtractValue("redis://localhost:6379")
	if got != nil && isValidTarget(got) {
		t.Error("localhost should be filtered")
	}
	got = parseExtractValue("mysql://user:pass@${DB_HOST}:3306/db")
	if got != nil && isValidTarget(got) {
		t.Error("${VAR} should be filtered")
	}
}
