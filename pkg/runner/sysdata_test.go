//go:build linux
// +build linux

package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
	"github.com/chainreactors/proton/sysinfo"
	"github.com/stretchr/testify/assert"
)

func TestReadProcessEnv(t *testing.T) {
	data, err := sysinfo.ReadProcessEnv(os.Getpid())
	assert.NoError(t, err)
	assert.True(t, len(data) > 0)
	assert.Contains(t, string(data), "PATH=")
}

func TestReadProcessCmdline(t *testing.T) {
	data, err := sysinfo.ReadProcessCmdline(os.Getpid())
	assert.NoError(t, err)
	assert.True(t, len(data) > 0)
}

func TestReadProcessFDs(t *testing.T) {
	data, err := sysinfo.ReadProcessFDs(os.Getpid())
	assert.NoError(t, err)
	assert.True(t, len(data) > 0)
}

func TestReadProcessConns(t *testing.T) {
	data, err := sysinfo.ReadProcessConns(os.Getpid())
	assert.NoError(t, err)
	_ = data
}

func TestReadProcessPipes(t *testing.T) {
	data, err := sysinfo.ReadProcessPipes(os.Getpid())
	assert.NoError(t, err)
	_ = data
}

func TestScanProcessEnvWithSysRules(t *testing.T) {
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}
	sysReq := &sys.Request{Source: sysinfo.SourceEnv}
	sysReq.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`PATH=\S+`}},
	}
	sysReq.Compile(execOpts)

	rules := []sysRule{{
		ID: "env-test", Name: "Env Test", Severity: "high",
		Request: sysReq,
	}}

	var findings []file.Finding
	err := scanProcessWithSysRules(rules, execOpts, os.Getpid(), func(f file.Finding) {
		findings = append(findings, f)
	})
	assert.NoError(t, err)
	assert.True(t, len(findings) > 0, "should find PATH in env")
	assert.Contains(t, findings[0].FilePath, "pid:")
	assert.Contains(t, findings[0].FilePath, ":env")
}

func TestScanProcessMultiSource(t *testing.T) {
	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}

	envReq := &sys.Request{Source: sysinfo.SourceEnv}
	envReq.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`HOME=\S+`}},
	}
	envReq.Compile(execOpts)

	fdReq := &sys.Request{Source: sysinfo.SourceFD}
	fdReq.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`/dev/\S+`}},
	}
	fdReq.Compile(execOpts)

	rules := []sysRule{
		{ID: "env", Name: "Env", Severity: "high", Request: envReq},
		{ID: "fd", Name: "FD", Severity: "info", Request: fdReq},
	}

	var findings []file.Finding
	err := scanProcessWithSysRules(rules, execOpts, os.Getpid(), func(f file.Finding) {
		findings = append(findings, f)
	})
	assert.NoError(t, err)
	assert.True(t, len(findings) > 0, "should find something from env or fd")

	sources := make(map[string]bool)
	for _, f := range findings {
		if strings.Contains(f.FilePath, ":env") {
			sources["env"] = true
		}
		if strings.Contains(f.FilePath, ":fd") {
			sources["fd"] = true
		}
	}
	assert.True(t, sources["env"], "should have env findings")
}

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"0100007F:0050", "127.0.0.1:80"},
		{"00000000:0000", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sysinfo.ParseHexAddr(tt.input)
			assert.Equal(t, tt.expect, got)
		})
	}
}
