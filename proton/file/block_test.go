package file

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/assert"
)

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

func TestScanBlock(t *testing.T) {
	scanner := memScanner([]string{`PROTON_BLOCK_TEST_[A-Z0-9_]+`})

	data := []byte("prefix\x00\x00PROTON_BLOCK_TEST_SECRET123\x00\x00suffix")
	findings := scanner.ScanBlock(data, "test:label", scanner.Groups[0])

	assert.True(t, len(findings) > 0, "ScanBlock should find the pattern")
	if len(findings) > 0 {
		assert.Equal(t, "test:label", findings[0].FilePath)
		assert.Contains(t, findings[0].Extracts[0].Value, "PROTON_BLOCK_TEST_SECRET123")
	}
}

func TestScanMemBlock(t *testing.T) {
	scanner := memScanner([]string{`PROTON_MEM_TEST_SECRET_[A-Z0-9_]+`})

	data := []byte("some prefix data\x00\x00PROTON_MEM_TEST_SECRET_XYZ789\x00\x00more binary data")
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

	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	copy(data[2000:], []byte("AKIAIOSFODNN7EXAMPLE1"))

	findings := scanner.scanMemBlock(data, 0x400000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0, "should find AWS key in binary data")
	if len(findings) > 0 {
		assert.Contains(t, findings[0].Extracts[0].Value, "AKIAIOSFODNN7EXAMPLE")
		assert.Equal(t, 0x400000+2000, findings[0].Extracts[0].Offset)
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
	assert.Equal(t, 0, len(findings))
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

	pos := MemWindowSize - MemOverlapSize/2
	data := make([]byte, MemWindowSize*2)
	copy(data[pos:], []byte("DEDUP_TOKEN_ALPHA"))

	findings := scanner.scanMemBlock(data, 0x1000, "pid:1", scanner.Groups[0])
	assert.True(t, len(findings) > 0)
	totalExtracts := 0
	for _, f := range findings {
		totalExtracts += len(f.Extracts)
	}
	assert.Equal(t, 1, totalExtracts, "overlap dedup should produce exactly one extract")
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

func makeMemScanner() *Scanner {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	reqs := []*Request{
		{
			Extensions: []string{"all"},
			Operators: operators.Operators{
				Extractors: []*operators.Extractor{
					{Type: "regex", Regex: []string{
						`(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+`,
						`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9]{16,}`,
						`(?:AKIA|ASIA)[A-Z0-9]{16}`,
						`-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----`,
						`ghp_[A-Za-z0-9]{36}`,
					}},
				},
			},
		},
	}
	for _, req := range reqs {
		req.Compile(execOpts)
	}
	return NewScanner([]Rule{{
		ID: "bench", Name: "Bench", Severity: "info",
		Requests: reqs,
	}}, execOpts)
}

func generateRealisticData(size int, seedSecrets int) []byte {
	data := make([]byte, size)
	rng := rand.New(rand.NewSource(42))
	rng.Read(data)

	textFragments := []string{
		"HOME=/home/user\x00PATH=/usr/bin:/bin\x00SHELL=/bin/bash\x00",
		"LANG=en_US.UTF-8\x00TERM=xterm-256color\x00",
		"http://localhost:8080/api/v1/health\x00",
		"Content-Type: application/json\r\nAuthorization: Bearer ",
		"SELECT * FROM users WHERE id = $1\x00",
	}
	for i := 0; i < 20; i++ {
		pos := rng.Intn(size - 1024)
		copy(data[pos:], textFragments[i%len(textFragments)])
	}

	secrets := []string{
		"password: SuperSecret123!",
		"api_key=AKIAIOSFODNN7EXAMPLE123456",
		"ghp_xyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
		"-----BEGIN RSA PRIVATE KEY-----",
		"apiKey: abcdef1234567890abcdef1234567890",
	}
	for i := 0; i < seedSecrets; i++ {
		pos := rng.Intn(size - 256)
		copy(data[pos:], secrets[i%len(secrets)])
	}

	return data
}

func BenchmarkMemBlockThroughput(b *testing.B) {
	scanner := makeMemScanner()
	group := scanner.Groups[0]
	data := generateRealisticData(64<<20, 20) // 64MB

	windows := []int{
		4 << 10,   // 4KB
		16 << 10,  // 16KB
		32 << 10,  // 32KB
		64 << 10,  // 64KB
		128 << 10, // 128KB
		192 << 10, // 192KB
		256 << 10, // 256KB
		384 << 10, // 384KB
		512 << 10, // 512KB
		768 << 10, // 768KB
		1 << 20,   // 1MB
		2 << 20,   // 2MB
		4 << 20,   // 4MB
	}

	for _, w := range windows {
		overlap := w / 64
		if overlap < 512 {
			overlap = 512
		}
		if overlap > 8192 {
			overlap = 8192
		}
		name := formatSize(w)
		b.Run(name, func(b *testing.B) {
			MemWindowSize = w
			MemOverlapSize = overlap
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.scanMemBlock(data, 0x7f0000000000, "pid:bench", group)
			}
		})
	}
}

func formatSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
