//go:build windows

package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
	"github.com/chainreactors/proton/sysinfo"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestScanRegistryWithFileScanner(t *testing.T) {
	marker, path := createRegistryMarker(t)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}
	req := &file.Request{
		Extensions: []string{"all"},
	}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{marker}},
	}
	require.NoError(t, req.Compile(execOpts))
	scanner := file.NewScanner([]file.Rule{{
		ID: "registry-file", Name: "Registry File", Severity: "info",
		Requests: []*file.Request{req},
	}}, execOpts)

	var findings []file.Finding
	err := scanRegistry(scanner, sysinfo.RegistryWalkOptions{
		Targets: []sysinfo.RegistryTarget{{Root: "HKCU", Path: path, MaxDepth: 1}},
	}, func(f file.Finding) {
		findings = append(findings, f)
	})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	require.True(t, strings.HasPrefix(findings[0].FilePath, "registry:HKCU\\"))
}

func TestScanRegistryWithSysRules(t *testing.T) {
	marker, path := createRegistryMarker(t)
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}
	sysReq := &sys.Request{
		Source: sysinfo.SourceRegistry,
		Paths:  []string{`HKCU\` + path},
	}
	sysReq.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{marker}},
	}
	require.NoError(t, sysReq.Compile(execOpts))

	var findings []file.Finding
	err := scanRegistryWithSysRules([]sysRule{{
		ID: "registry-sys", Name: "Registry Sys", Severity: "high",
		Request: sysReq,
	}}, execOpts, func(f file.Finding) {
		findings = append(findings, f)
	})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	require.Contains(t, findings[0].FilePath, "registry:HKCU\\")
}

func TestRunnerAllowsRegistrySysTemplateWithoutFileTarget(t *testing.T) {
	marker, path := createRegistryMarker(t)
	tmplPath := filepath.Join(t.TempDir(), "registry-template.yaml")
	body := fmt.Sprintf(`id: registry-template
info:
  name: Registry Template
  severity: high
sys:
  - source: registry
    paths:
      - %q
    extractors:
      - type: regex
        regex:
          - %q
`, `HKCU\`+path, marker)
	require.NoError(t, os.WriteFile(tmplPath, []byte(body), 0600))

	r, err := New(&Config{
		Templates: []string{tmplPath},
		Output:    "json",
		Quiet:     true,
	})
	require.NoError(t, err)
	require.NoError(t, r.Run())
}

func createRegistryMarker(t *testing.T) (string, string) {
	t.Helper()
	marker := fmt.Sprintf("PROTON_RUNNER_REGISTRY_%d", time.Now().UnixNano())
	path := fmt.Sprintf(`Software\Chainreactors\ProtonRunnerRegistryTest_%d`, time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	require.NoError(t, err)
	require.NoError(t, key.SetStringValue("Marker", marker))
	require.NoError(t, key.Close())
	t.Cleanup(func() {
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
	})
	return marker, path
}
