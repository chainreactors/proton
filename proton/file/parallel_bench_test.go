package file

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// createTestFilesDir creates a directory with count files, each approximately
// 10 KB of realistic content suitable for regex scanning.
func createTestFilesDir(b *testing.B, count int) string {
	b.Helper()
	dir := b.TempDir()

	codeLines := []string{
		"package service",
		"",
		"import (",
		`    "context"`,
		`    "fmt"`,
		`    "net/http"`,
		")",
		"",
		"type Handler struct {",
		"    DB     *Database",
		"    Logger *Logger",
		"}",
		"",
		"func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {",
		`    ctx := r.Context()`,
		`    userID := r.URL.Query().Get("user_id")`,
		`    if userID == "" {`,
		`        http.Error(w, "missing user_id", http.StatusBadRequest)`,
		"        return",
		"    }",
		`    user, err := h.DB.GetUser(ctx, userID)`,
		"    if err != nil {",
		`        h.Logger.Error("failed to get user", "error", err, "user_id", userID)`,
		`        http.Error(w, "internal error", http.StatusInternalServerError)`,
		"        return",
		"    }",
		`    fmt.Fprintf(w, "Hello, %s! Your IP is %s\n", user.Name, "192.168.1.42")`,
		"}",
		"",
		`var apiKey = "test_key_AbCdEfGhIjKlMnOpQrStUvWx"`,
		`var dbPassword = "s3cr3t_p4ssw0rd_12345"`,
		`var contactEmail = "admin@example.com"`,
		`var serverAddr = "10.0.0.1:8080"`,
		"",
	}

	var sb strings.Builder
	for sb.Len() < 10*1024 {
		for _, line := range codeLines {
			sb.WriteString(line)
			sb.WriteByte('\n')
			if sb.Len() >= 10*1024 {
				break
			}
		}
	}
	content := sb.String()

	for i := 0; i < count; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file_%04d.go", i))
		if err := os.WriteFile(name, []byte(content), 0644); err != nil {
			b.Fatal(err)
		}
	}
	return dir
}

// processFileForBench simulates the real workload: read the file, run 5 regex
// patterns, and count matches.
func processFileForBench(path string, regexes []*regexp.Regexp) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	content := string(data)
	total := 0
	for _, re := range regexes {
		matches := re.FindAllString(content, -1)
		total += len(matches)
	}
	return total
}

func BenchmarkProcessFiles(b *testing.B) {
	// Compile the 5 regex patterns once
	patterns := []string{
		`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`,
		`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?\S+`,
		`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?\S+`,
		`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`,
	}
	regexes := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		regexes[i] = regexp.MustCompile(p)
	}

	fileCounts := []struct {
		name  string
		count int
	}{
		{"10files", 10},
		{"100files", 100},
	}

	for _, fc := range fileCounts {
		dir := createTestFilesDir(b, fc.count)

		// Collect file paths
		var files []string
		entries, err := os.ReadDir(dir)
		if err != nil {
			b.Fatal(err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, filepath.Join(dir, e.Name()))
			}
		}

		b.Run("Sequential/"+fc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var total int
				for _, f := range files {
					total += processFileForBench(f, regexes)
				}
				if total < 0 {
					b.Fatal("unreachable")
				}
			}
		})

		b.Run("Parallel/"+fc.name, func(b *testing.B) {
			numWorkers := runtime.NumCPU()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ch := make(chan string, len(files))
				for _, f := range files {
					ch <- f
				}
				close(ch)

				var wg sync.WaitGroup
				results := make([]int, numWorkers)
				for w := 0; w < numWorkers; w++ {
					wg.Add(1)
					go func(workerID int) {
						defer wg.Done()
						localTotal := 0
						for path := range ch {
							localTotal += processFileForBench(path, regexes)
						}
						results[workerID] = localTotal
					}(w)
				}
				wg.Wait()

				var total int
				for _, r := range results {
					total += r
				}
				if total < 0 {
					b.Fatal("unreachable")
				}
			}
		})
	}
}
