package file

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	mmap "github.com/edsrzf/mmap-go"
)

// createTestFile creates a temporary file of approximately the given size with
// realistic text content. Lines are ~80 characters long and some contain
// "BEGIN RSA PRIVATE KEY" to allow pattern matching simulation.
func createTestFile(b *testing.B, size int) string {
	b.Helper()

	var sb strings.Builder
	sb.Grow(size + 256)

	// Realistic code-like lines with occasional secrets
	lines := []string{
		"package main",
		"",
		"import (",
		`    "fmt"`,
		`    "os"`,
		`    "strings"`,
		")",
		"",
		"func main() {",
		`    fmt.Println("Hello, world!")`,
		`    path := os.Getenv("HOME")`,
		`    if strings.Contains(path, "user") {`,
		`        fmt.Printf("Home: %s\n", path)`,
		"    }",
		"}",
		"",
		"// Configuration values",
		`var apiEndpoint = "https://api.example.com/v2/data"`,
		`var timeout = 30`,
		`var maxRetries = 3`,
		"",
		"// -----BEGIN RSA PRIVATE KEY-----",
		"// MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wRDEGGmKM5Jc7TrKSEyA+iz",
		"// -----END RSA PRIVATE KEY-----",
		"",
		"func processData(input []byte) ([]byte, error) {",
		`    if len(input) == 0 {`,
		`        return nil, fmt.Errorf("empty input")`,
		"    }",
		`    result := make([]byte, len(input))`,
		"    copy(result, input)",
		"    return result, nil",
		"}",
	}

	lineIdx := 0
	for sb.Len() < size {
		line := lines[lineIdx%len(lines)]
		// Pad short lines to ~80 chars
		if len(line) < 78 {
			line = line + strings.Repeat(" ", 78-len(line))
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		lineIdx++
	}

	content := sb.String()
	if len(content) > size {
		content = content[:size]
	}

	f, err := os.CreateTemp(b.TempDir(), "bench-*.txt")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		b.Fatal(err)
	}
	name := f.Name()
	f.Close()
	return name
}

func BenchmarkFileRead(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, sz := range sizes {
		filePath := createTestFile(b, sz.size)

		b.Run("BufioScanner/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f, err := os.Open(filePath)
				if err != nil {
					b.Fatal(err)
				}
				scanner := bufio.NewScanner(f)
				var matchCount int
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "PRIVATE KEY") {
						matchCount++
					}
				}
				f.Close()
				if matchCount < 0 {
					b.Fatal("unreachable")
				}
			}
		})

		b.Run("Mmap/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f, err := os.Open(filePath)
				if err != nil {
					b.Fatal(err)
				}
				info, err := f.Stat()
				if err != nil {
					f.Close()
					b.Fatal(err)
				}
				if info.Size() == 0 {
					f.Close()
					continue
				}
				mapped, err := mmap.Map(f, mmap.RDONLY, 0)
				if err != nil {
					f.Close()
					b.Fatal(err)
				}

				var matchCount int
				data := []byte(mapped)
				for len(data) > 0 {
					idx := bytes.IndexByte(data, '\n')
					var line []byte
					if idx >= 0 {
						line = data[:idx]
						data = data[idx+1:]
					} else {
						line = data
						data = nil
					}
					if bytes.Contains(line, []byte("PRIVATE KEY")) {
						matchCount++
					}
				}

				mapped.Unmap()
				f.Close()
				if matchCount < 0 {
					b.Fatal("unreachable")
				}
			}
		})

		b.Run("OsReadFile/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				content, err := os.ReadFile(filePath)
				if err != nil {
					b.Fatal(err)
				}
				var matchCount int
				lines := bytes.Split(content, []byte("\n"))
				for _, line := range lines {
					if bytes.Contains(line, []byte("PRIVATE KEY")) {
						matchCount++
					}
				}
				if matchCount < 0 {
					b.Fatal("unreachable")
				}
			}
		})
	}

	// Report file sizes for context
	for _, sz := range sizes {
		b.Log(fmt.Sprintf("File size %s = %d bytes", sz.name, sz.size))
	}
}
