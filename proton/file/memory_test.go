package file

import (
	"os"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/assert"
)

var testMemSecret = "PROTON_MEM_TEST_SECRET_XYZ789_KEEPALIVE"

func memScanner(patterns []string) *Scanner {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req := &Request{Extensions: []string{"all"}}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: patterns},
	}
	req.Compile(execOpts)
	return NewScanner([]Rule{{
		ID: "mem-test", Name: "Memory Test", Severity: "info",
		Requests: []*Request{req},
	}}, execOpts)
}

func memScannerWithMatchers(words []string) *Scanner {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req := &Request{Extensions: []string{"all"}}
	req.Matchers = []*operators.Matcher{
		{Type: "word", Words: words},
	}
	req.Compile(execOpts)
	return NewScanner([]Rule{{
		ID: "word-test", Name: "Word Test", Severity: "info",
		Requests: []*Request{req},
	}}, execOpts)
}

func TestScanMemBlock(t *testing.T) {
	scanner := memScanner([]string{`PROTON_MEM_TEST_SECRET_[A-Z0-9_]+`})

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
	scanner := memScanner([]string{`BOUNDARY_PATTERN_[A-Z]+`})

	pos := MemWindowSize - MemOverlapSize/2
	data := make([]byte, MemWindowSize+1024)
	copy(data[pos:], []byte("BOUNDARY_PATTERN_FOUND"))

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "should find pattern near window boundary")
}

func TestScanMemBlockCaseInsensitive(t *testing.T) {
	scanner := memScanner([]string{`(?i)secret_token_[a-z0-9]+`})

	data := []byte("\x00\x00SECRET_TOKEN_AbCdEf123\x00\x00")
	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "case-insensitive regex should match mixed-case data")
	if len(findings) > 0 {
		assert.Contains(t, findings[0].Extracts[0].Value, "SECRET_TOKEN_AbCdEf123")
	}
}

func TestScanMemBlockCaseSensitive(t *testing.T) {
	scanner := memScanner([]string{`SECRET_EXACT_[A-Z]+`})

	data := []byte("\x00secret_exact_abc\x00SECRET_EXACT_XYZ\x00")
	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0)
	if len(findings) > 0 {
		assert.Equal(t, "SECRET_EXACT_XYZ", findings[0].Extracts[0].Value)
	}
}

func TestScanMemBlockBinaryData(t *testing.T) {
	scanner := memScanner([]string{`AKIA[A-Z0-9]{16,}`})

	// embed secret in binary noise
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	secret := []byte("AKIAIOSFODNN7EXAMPLE1")
	copy(data[2000:], secret)

	findings := scanner.scanMemBlock(data, 0x400000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "should find AWS key in binary data")
	if len(findings) > 0 {
		assert.Contains(t, findings[0].Extracts[0].Value, "AKIAIOSFODNN7EXAMPLE")
		expectedAddr := 0x400000 + 2000
		assert.Equal(t, expectedAddr, findings[0].Extracts[0].Offset)
	}
}

func TestScanMemBlockNullBytes(t *testing.T) {
	scanner := memScanner([]string{`password=[^\x00]+`})

	data := []byte("\x00\x00\x00password=hunter2\x00\x00\x00")
	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "should match across null byte boundaries")
}

func TestScanMemBlockWordMatcher(t *testing.T) {
	scanner := memScannerWithMatchers([]string{"MAGIC_WORD_PRESENT"})

	data := []byte("\x00binary\x00MAGIC_WORD_PRESENT\x00more\x00")
	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "word matcher should work on binary memory")
}

func TestScanMemBlockNoMatch(t *testing.T) {
	scanner := memScanner([]string{`THIS_WILL_NEVER_MATCH_[A-Z]+`})

	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.Equal(t, 0, len(findings), "should find nothing in random data")
}

func TestScanMemBlockMultiplePatterns(t *testing.T) {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req := &Request{Extensions: []string{"all"}}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: []string{`AKIA[A-Z0-9]{16,}`}},
		{Type: "regex", Regex: []string{`ghp_[A-Za-z0-9]{36}`}},
	}
	req.Compile(execOpts)
	scanner := NewScanner([]Rule{{
		ID: "multi", Name: "Multi", Severity: "info",
		Requests: []*Request{req},
	}}, execOpts)

	data := []byte("prefix AKIAIOSFODNN7EXAMPLE1 middle ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234 suffix")

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0)
	values := make(map[string]bool)
	for _, f := range findings {
		for _, e := range f.Extracts {
			values[e.Value] = true
		}
	}
	foundAWS := false
	foundGH := false
	for v := range values {
		if len(v) >= 20 && v[:4] == "AKIA" {
			foundAWS = true
		}
		if len(v) >= 40 && v[:4] == "ghp_" {
			foundGH = true
		}
	}
	assert.True(t, foundAWS, "should find AWS key")
	assert.True(t, foundGH, "should find GitHub token")
}

func TestScanMemBlockDeduplication(t *testing.T) {
	scanner := memScanner([]string{`DEDUP_TOKEN_[A-Z]+`})

	// place secret in the overlap zone so two windows both see it
	pos := MemWindowSize - MemOverlapSize/2
	data := make([]byte, MemWindowSize*2)
	copy(data[pos:], []byte("DEDUP_TOKEN_ALPHA"))

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0)
	// should deduplicate: only one finding, not two
	totalExtracts := 0
	for _, f := range findings {
		totalExtracts += len(f.Extracts)
	}
	assert.Equal(t, 1, totalExtracts, "overlap dedup should produce exactly one extract")
}

func TestScanProcessSelf(t *testing.T) {
	pid := os.Getpid()
	r, err := newMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own process memory: %v", err)
	}
	r.Close()

	scanner := memScanner([]string{`PROTON_MEM_TEST_SECRET_[A-Z0-9_]+`})

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
		{"vvar region", MemoryRegion{Perms: "r--p", MappedFile: "[vvar]"}, false, true},
		{"writable mapped", MemoryRegion{Perms: "rw-p", MappedFile: "/tmp/data.bin"}, false, true},
		{"readonly mapped lib", MemoryRegion{Perms: "r--p", MappedFile: "/lib/libc.so"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanRegion(tt.region, MemoryScanOptions{ScanAll: tt.all})
			assert.Equal(t, tt.want, got)
		})
	}
}


func TestAsciiLowerInto(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"HELLO", "hello"},
		{"Hello World", "hello world"},
		{"already_lower", "already_lower"},
		{"MiXeD-CaSe_123", "mixed-case_123"},
		{"\x00BINARY\xff", "\x00binary\xff"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			src := []byte(tt.input)
			dst := make([]byte, len(src))
			asciiLowerInto(dst, src)
			assert.Equal(t, tt.expect, string(dst))
		})
	}
}
