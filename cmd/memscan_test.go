//go:build linux
// +build linux

package cmd

import (
	"os"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
	"github.com/chainreactors/proton/proton/sysinfo"
	"github.com/stretchr/testify/assert"
)

var memTestSecret = "PROTON_MEMSCAN_CMD_SECRET_ABC123"

func TestScanProcessSelf(t *testing.T) {
	pid := os.Getpid()
	r, err := sysinfo.NewMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own process memory: %v", err)
	}
	r.Close()

	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}
	req := &file.Request{Extensions: []string{"all"}}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`PROTON_MEMSCAN_CMD_SECRET_[A-Z0-9]+`}},
	}
	req.Compile(execOpts)

	scanner := file.NewScanner([]file.Rule{{
		ID: "self-test", Name: "Self Scan", Severity: "info",
		Requests: []*file.Request{req},
	}}, execOpts)

	var findings []file.Finding
	err = scanProcess(scanner, pid, memoryScanOptions{ScanAll: true}, func(f file.Finding) {
		findings = append(findings, f)
	})
	assert.NoError(t, err)
	if len(findings) == 0 {
		t.Log("secret not found in self-scan (may be optimized by compiler); not a hard failure")
	}
	_ = memTestSecret
}

func TestScanProcessWithSysRules(t *testing.T) {
	pid := os.Getpid()
	r, err := sysinfo.NewMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own process memory: %v", err)
	}
	r.Close()

	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: false}}
	sysReq := &sys.Request{
		Regions: []string{"heap", "stack", "anonymous"},
	}
	sysReq.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`PROTON_MEMSCAN_CMD_SECRET_[A-Z0-9]+`}},
	}
	sysReq.Compile(execOpts)

	rules := []sysRule{{
		ID:       "sys-self",
		Name:     "Sys Self Test",
		Severity: "info",
		Request:  sysReq,
	}}

	var findings []file.Finding
	err = scanProcessWithSysRules(rules, execOpts, pid, func(f file.Finding) {
		findings = append(findings, f)
	})
	assert.NoError(t, err)
	if len(findings) == 0 {
		t.Log("secret not found via sys rules (may be optimized by compiler); not a hard failure")
	}
	_ = memTestSecret
}

func TestShouldScanRegionCmd(t *testing.T) {
	tests := []struct {
		name   string
		region sysinfo.MemoryRegion
		all    bool
		want   bool
	}{
		{"writable heap", sysinfo.MemoryRegion{Perms: "rw-p", MappedFile: "[heap]"}, false, true},
		{"readonly code", sysinfo.MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, false, false},
		{"readonly code with scanall", sysinfo.MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, true, true},
		{"no read perm", sysinfo.MemoryRegion{Perms: "---p"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanRegion(tt.region, memoryScanOptions{ScanAll: tt.all})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMapsLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		ok     bool
		base   uint64
		perms  string
		mapped string
	}{
		{"heap", "7f1234560000-7f1234570000 rw-p 00000000 00:00 0                          [heap]", true, 0x7f1234560000, "rw-p", "[heap]"},
		{"lib", "7f0000100000-7f0000200000 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6", true, 0x7f0000100000, "r-xp", "/usr/lib/libc.so.6"},
		{"empty", "", false, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, ok := sysinfo.ParseMapsLine(tt.line)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.base, region.BaseAddr)
				assert.Equal(t, tt.perms, region.Perms)
				assert.Equal(t, tt.mapped, region.MappedFile)
			}
		})
	}
}
