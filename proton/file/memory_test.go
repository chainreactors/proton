package file

import (
	"os"
	"runtime"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/assert"
)

var testMemSecret = "PROTON_MEM_TEST_SECRET_XYZ789_KEEPALIVE"

func TestScanMemBlock(t *testing.T) {
	req := &Request{}
	req.Extensions = []string{"all"}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`PROTON_MEM_TEST_SECRET_[A-Z0-9_]+`}},
	}
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	err := req.Compile(execOpts)
	assert.NoError(t, err)

	rule := Rule{
		ID:       "mem-test",
		Name:     "Memory Test",
		Severity: "info",
		Requests: []*Request{req},
	}
	scanner := NewScanner([]Rule{rule}, execOpts)
	assert.True(t, len(scanner.Groups) > 0)

	data := []byte("some prefix data\x00\x00" + testMemSecret + "\x00\x00more binary data")
	findings := scanner.scanMemBlock(data, 0x7f0000001000, "pid:999", scanner.Groups[0])

	assert.True(t, len(findings) > 0, "should find the secret in memory block")
	if len(findings) > 0 {
		assert.Equal(t, "mem-test", findings[0].TemplateID)
		assert.Equal(t, "pid:999", findings[0].FilePath)
		assert.True(t, len(findings[0].Extracts) > 0)
		assert.Contains(t, findings[0].Extracts[0].Value, "PROTON_MEM_TEST_SECRET")
		assert.True(t, findings[0].Extracts[0].Offset > 0, "offset should be virtual address")
	}
}

func TestScanMemBlockSlidingWindow(t *testing.T) {
	req := &Request{}
	req.Extensions = []string{"all"}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`BOUNDARY_PATTERN_[A-Z]+`}},
	}
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req.Compile(execOpts)

	scanner := NewScanner([]Rule{{
		ID: "boundary-test", Name: "Boundary", Severity: "info",
		Requests: []*Request{req},
	}}, execOpts)

	pos := MemWindowSize - MemOverlapSize/2
	data := make([]byte, MemWindowSize+1024)
	copy(data[pos:], []byte("BOUNDARY_PATTERN_FOUND"))

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "should find pattern near window boundary")
}

func TestScanProcessSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	// Check if we can read our own /proc/pid/mem
	pid := os.Getpid()
	r, err := newMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own process memory: %v", err)
	}
	r.Close()

	req := &Request{}
	req.Extensions = []string{"all"}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`PROTON_MEM_TEST_SECRET_[A-Z0-9_]+`}},
	}
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req.Compile(execOpts)

	scanner := NewScanner([]Rule{{
		ID: "self-test", Name: "Self Scan", Severity: "info",
		Requests: []*Request{req},
	}}, execOpts)

	var findings []Finding
	err = scanner.ScanProcess(pid, MemoryScanOptions{ScanAll: true}, func(f Finding) {
		findings = append(findings, f)
	})
	assert.NoError(t, err)
	assert.True(t, len(findings) > 0, "should find testMemSecret in own process memory")

	_ = testMemSecret // keep alive
}

func TestShouldScanRegion(t *testing.T) {
	tests := []struct {
		name   string
		region MemoryRegion
		all    bool
		want   bool
	}{
		{"writable heap", MemoryRegion{Perms: "rw-p", MappedFile: "[heap]"}, false, true},
		{"writable stack", MemoryRegion{Perms: "rw-p", MappedFile: "[stack]"}, false, true},
		{"writable anonymous", MemoryRegion{Perms: "rw-p", MappedFile: ""}, false, true},
		{"readonly code", MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, false, false},
		{"readonly code with scanall", MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, true, true},
		{"no read perm", MemoryRegion{Perms: "---p"}, false, false},
		{"no read perm with scanall", MemoryRegion{Perms: "---p"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanRegion(tt.region, MemoryScanOptions{ScanAll: tt.all})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMapsLine(t *testing.T) {
	line := "7f1234560000-7f1234570000 rw-p 00000000 00:00 0                          [heap]"
	region, ok := parseMapsLine(line)
	assert.True(t, ok)
	assert.Equal(t, uint64(0x7f1234560000), region.BaseAddr)
	assert.Equal(t, uint64(0x10000), region.Size)
	assert.Equal(t, "rw-p", region.Perms)
	assert.Equal(t, "[heap]", region.MappedFile)
}
