package file

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

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

func BenchmarkProcessScanThroughput(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux only")
	}
	pid := os.Getpid()
	if _, err := newMemoryReader(pid); err != nil {
		b.Skipf("cannot read own memory: %v", err)
	}

	scanner := makeMemScanner()

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
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.ScanProcess(pid, MemoryScanOptions{ScanAll: false}, func(f Finding) {})
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
