package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	oldarchiver "github.com/mholt/archiver"
	re2 "github.com/wasilibs/go-re2"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func createBenchFiles(b *testing.B, dir string, count, sizeBytes int, matchRate float64) {
	b.Helper()
	var sb strings.Builder

	filler := "func processData(input []byte) ([]byte, error) { return input, nil }\n"
	secret := "password = hunter2_secret_value\n"

	for i := 0; i < count; i++ {
		sb.Reset()
		sb.Grow(sizeBytes + 256)
		lineNum := 0
		for sb.Len() < sizeBytes {
			if matchRate > 0 && float64(lineNum%100)/100.0 < matchRate {
				sb.WriteString(secret)
			} else {
				sb.WriteString(filler)
			}
			lineNum++
		}
		name := filepath.Join(dir, fmt.Sprintf("file_%05d.txt", i))
		if err := os.WriteFile(name, []byte(sb.String()[:sizeBytes]), 0644); err != nil {
			b.Fatal(err)
		}
	}
}

func makeBenchRules(count int) []Rule {
	rules := make([]Rule, count)
	baseWords := []string{"password", "secret_key", "api_token", "private_key", "access_key"}
	for i := 0; i < count; i++ {
		word := baseWords[i%len(baseWords)]
		req := &Request{
			ID:         fmt.Sprintf("bench-rule-%d", i),
			MaxSize:    "1Gb",
			Extensions: []string{"all"},
			Operators: operators.Operators{
				Matchers: []*operators.Matcher{{
					Part: "raw", Type: "word", Words: []string{word},
				}},
				Extractors: []*operators.Extractor{{
					Part:       "raw",
					Type:       "regex",
					Regex:      []string{fmt.Sprintf(`%s\s*=\s*(\S+)`, word)},
					RegexGroup: 1,
				}},
			},
		}
		opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
		if err := req.Compile(opts); err != nil {
			panic(err)
		}
		rules[i] = Rule{
			ID:       req.ID,
			Name:     fmt.Sprintf("Bench Rule %d", i),
			Severity: "info",
			Requests: []*Request{req},
		}
	}
	return rules
}

func makeNaiveRegexps(count int) []*regexp.Regexp {
	baseWords := []string{"password", "secret_key", "api_token", "private_key", "access_key"}
	res := make([]*regexp.Regexp, count)
	for i := 0; i < count; i++ {
		word := baseWords[i%len(baseWords)]
		res[i] = regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*(\S+)`, word))
	}
	return res
}

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

// ---------------------------------------------------------------------------
// Scanner benchmarks
// ---------------------------------------------------------------------------

func BenchmarkScanner_SmallFiles(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 1000, 1024, 0.01)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		b.ReportMetric(float64(1000)/b.Elapsed().Seconds(), "files/sec")
	}
}

func BenchmarkScanner_LargeFiles(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 100*1024, 0.01)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		_ = count
	}
}

func BenchmarkScanner_ManyTemplates(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 10*1024, 0.01)
	rules := makeBenchRules(50)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		_ = count
	}
}

func BenchmarkScanner_LowMatchRate(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 1000, 1024, 0)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		_ = count
	}
}

func BenchmarkScanner_HighMatchRate(b *testing.B) {
	dir := b.TempDir()
	createBenchFiles(b, dir, 100, 10*1024, 0.5)
	rules := makeBenchRules(5)
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	scanner := NewScanner(rules, opts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		scanDir(scanner, dir, func(f Finding) { count++ })
		_ = count
	}
}

func BenchmarkProcessFile(b *testing.B) {
	for _, tc := range []struct {
		name      string
		sizeBytes int
		matchRate float64
		rules     int
	}{
		{"1KB_5rules", 1024, 0.05, 5},
		{"100KB_5rules", 100 * 1024, 0.01, 5},
		{"1KB_50rules", 1024, 0.05, 50},
		{"100KB_50rules", 100 * 1024, 0.01, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			dir := b.TempDir()
			createBenchFiles(b, dir, 1, tc.sizeBytes, tc.matchRate)
			filePath := filepath.Join(dir, "file_00000.txt")
			rules := makeBenchRules(tc.rules)
			opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
			scanner := NewScanner(rules, opts)
			group := scanner.Groups[0]

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, c := range scanner.ReadFile(filePath, group) {
					scanner.ScanData(c.Data, c.Label, group)
				}
			}
		})
	}
}

func BenchmarkNaiveFile(b *testing.B) {
	for _, tc := range []struct {
		name      string
		sizeBytes int
		matchRate float64
		rules     int
	}{
		{"1KB_5rules", 1024, 0.05, 5},
		{"100KB_5rules", 100 * 1024, 0.01, 5},
		{"1KB_50rules", 1024, 0.05, 50},
		{"100KB_50rules", 100 * 1024, 0.01, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			dir := b.TempDir()
			createBenchFiles(b, dir, 1, tc.sizeBytes, tc.matchRate)
			filePath := filepath.Join(dir, "file_00000.txt")
			regexps := makeNaiveRegexps(tc.rules)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				data, _ := os.ReadFile(filePath)
				body := string(data)
				for _, re := range regexps {
					re.FindAllStringSubmatch(body, -1)
				}
			}
		})
	}
}

func BenchmarkLineLoop_StringConversion(b *testing.B) {
	line := []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz 1234", 3))

	b.Run("Unconditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s := string(line)
			_ = s
		}
	})

	b.Run("Lazy", func(b *testing.B) {
		b.ReportAllocs()
		needConvert := false
		for i := 0; i < b.N; i++ {
			var s string
			if needConvert {
				s = string(line)
			}
			_ = s
		}
	})
}

func BenchmarkFileResult_SliceAlloc(b *testing.B) {
	templateCount := 50
	matcherCount := 3
	extractorCount := 2

	b.Run("AllocPerFile", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			results := make([]fileResult, templateCount)
			for j := range results {
				results[j].matcherHits = make([][]matchHit, matcherCount)
				results[j].extractorHits = make([][]matchHit, extractorCount)
			}
			_ = results
		}
	})
}

func BenchmarkCompileRE2Patterns(b *testing.B) {
	patterns := []string{
		`password\s*=\s*\S+`,
		`secret_key\s*=\s*\S+`,
		`api_token\s*=\s*\S+`,
		`private_key\s*=\s*\S+`,
		`access_key\s*=\s*\S+`,
	}
	for _, p := range patterns {
		getOrCompileRE2(p)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getOrCompileRE2Slice(&patterns)
	}
}

// ---------------------------------------------------------------------------
// Parallel processing benchmarks
// ---------------------------------------------------------------------------

func BenchmarkProcessFiles(b *testing.B) {
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

// ---------------------------------------------------------------------------
// Archive benchmarks
// ---------------------------------------------------------------------------

const archiveBenchFileCount = 100
const archiveBenchFileSize = 10 * 1024

func generateFileContent(idx, size int) []byte {
	var sb strings.Builder
	sb.Grow(size + 256)
	filler := fmt.Sprintf("package main // file %d\nfunc init() {}\n", idx)
	secret := fmt.Sprintf("password = secret_value_%d\n", idx)
	lineNum := 0
	for sb.Len() < size {
		if lineNum == 5 {
			sb.WriteString(secret)
		} else {
			sb.WriteString(filler)
		}
		lineNum++
	}
	return []byte(sb.String()[:size])
}

func createBenchTar(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.tar")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("dir/file_%04d.txt", i),
			Size: int64(len(content)),
			Mode: 0644,
		})
		tw.Write(content)
	}
	tw.Close()
	f.Close()
	return path
}

func createBenchTarGz(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("dir/file_%04d.txt", i),
			Size: int64(len(content)),
			Mode: 0644,
		})
		tw.Write(content)
	}
	tw.Close()
	gw.Close()
	f.Close()
	return path
}

func createBenchZip(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.zip")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		w, _ := zw.Create(fmt.Sprintf("dir/file_%04d.txt", i))
		w.Write(content)
	}
	zw.Close()
	f.Close()
	return path
}

func readAllStdlibTar(path string) (int, int) {
	f, _ := os.Open(path)
	defer f.Close()
	tr := tar.NewReader(f)
	files, totalBytes := 0, 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, _ := io.ReadAll(tr)
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

func readAllStdlibTarGz(path string) (int, int) {
	f, _ := os.Open(path)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	defer gr.Close()
	tr := tar.NewReader(gr)
	files, totalBytes := 0, 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, _ := io.ReadAll(tr)
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

func readAllStdlibZip(path string) (int, int) {
	r, _ := zip.OpenReader(path)
	defer r.Close()
	files, totalBytes := 0, 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

func readAllArchiverV3(path string) (int, int) {
	archiveReader, _ := oldarchiver.ByExtension(path)
	if archiveReader == nil {
		return 0, 0
	}
	files, totalBytes := 0, 0
	switch inst := archiveReader.(type) {
	case oldarchiver.Walker:
		inst.Walk(path, func(file oldarchiver.File) error {
			if file.IsDir() {
				return nil
			}
			data, _ := io.ReadAll(file.ReadCloser)
			file.Close()
			totalBytes += len(data)
			if bytes.Contains(data, []byte("password")) {
				files++
			}
			return nil
		})
	case oldarchiver.Decompressor:
		f, err := os.Open(path)
		if err != nil {
			return 0, 0
		}
		defer f.Close()
		tmpFile, _ := os.CreateTemp("", "bench-decomp-*")
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()
		inst.Decompress(f, tmpFile)
		tmpFile.Seek(0, 0)
		data, _ := io.ReadAll(tmpFile)
		totalBytes = len(data)
		if bytes.Contains(data, []byte("password")) {
			files = 1
		}
	}
	return files, totalBytes
}

func BenchmarkArchive_Tar(b *testing.B) {
	tarPath := createBenchTar(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibTar(tarPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(tarPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}

func BenchmarkArchive_TarGz(b *testing.B) {
	tgzPath := createBenchTarGz(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibTarGz(tgzPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(tgzPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}

func BenchmarkArchive_Zip(b *testing.B) {
	zipPath := createBenchZip(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibZip(zipPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(zipPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Spray vs Proton comparison benchmarks
// ---------------------------------------------------------------------------

type sprayExtractor struct {
	name    string
	regexps []*regexp.Regexp
}

func newSprayExtractor(name string, patterns []string) *sprayExtractor {
	e := &sprayExtractor{name: name}
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			e.regexps = append(e.regexps, r)
		}
	}
	return e
}

func (e *sprayExtractor) Extract(body string) []string {
	var results []string
	for _, r := range e.regexps {
		matches := r.FindAllString(body, -1)
		results = append(results, matches...)
	}
	return results
}

type ruleSpec struct {
	name     string
	patterns []string
}

var sharedRules = []ruleSpec{
	{"jwt", []string{`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}`}},
	{"mail", []string{`[A-Za-z0-9_.]+@[A-Za-z0-9_.-]+\.[A-Za-z]{2,8}`}},
	{"phone", []string{`(\+?0?86-?)?1[3-9]\d{9}`}},
	{"ip", []string{`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`}},
	{"internal-ip", []string{`[^0-9]((127\.0\.0\.1)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))`}},
	{"password", []string{`(?i)(pass|pwd|passwd|password)[\s="':]+[A-Za-z0-9!@#$%^?.*&]{3,20}["']`}},
	{"username", []string{`(?i)(user|name|username)[\s="':]+[A-Za-z0-9!@%.]{3,20}[\s"']`}},
	{"aws-ak", []string{`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[a-zA-Z0-9]{16}`}},
	{"oss", []string{
		`(?i)access[_-]?key[_-]?id\s*[:=]\s*["']?([A-Za-z0-9/+=]{16,})["']?`,
		`(?i)access[_-]?key[_-]?secret\s*[:=]\s*["']?([A-Za-z0-9/+=]{16,})["']?`,
	}},
	{"rsa-key", []string{`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`}},
	{"jdbc", []string{`jdbc:[a-z0-9]+://[a-z0-9.\-_:;=/@?,&]+`}},
	{"github-token", []string{`[a-z0-9_-]*:[a-z0-9_-]+@github\.com[^\s"']*`}},
	{"bearer", []string{`(?i)["':]?\s*[Bb]earer\s+([A-Za-z0-9_.-]{20,})`}},
	{"api-key", []string{
		`(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,64})["']?`,
		`(?i)(secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,64})["']?`,
		`(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_.-]{16,})["']?`,
	}},
	{"aliyun-ak", []string{`LTAI[A-Za-z0-9]{12,20}`}},
	{"tencent-cloud", []string{`AKID[A-Za-z0-9]{13,20}`}},
	{"github-pat", []string{
		`ghp_[A-Za-z0-9]{36}`, `gho_[A-Za-z0-9]{36}`, `ghu_[A-Za-z0-9]{36}`,
		`ghs_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}`,
	}},
	{"stripe", []string{`[sr]k_(live|test)_[0-9a-zA-Z]{24,}`, `pk_(live|test)_[0-9a-zA-Z]{24,}`}},
	{"google-api", []string{`AIza[0-9A-Za-z_-]{35}`}},
	{"slack-webhook", []string{
		`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`,
		`xox[bpas]-[0-9]+-[0-9]+-[a-zA-Z0-9]+`,
	}},
	{"db-connection", []string{
		`mongodb(\+srv)?://[^\s"'<>]{10,}`, `redis://[^\s"'<>]{5,}`,
		`mysql://[^\s"'<>]{10,}`, `postgres(ql)?://[^\s"'<>]{10,}`,
	}},
}

func generateJSBody(size int, matchRate float64, rng *rand.Rand) []byte {
	secrets := []string{
		`var api_key = "sk_live_abc123def456ghi789jkl012mno345"`,
		`const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"`,
		`password = "Admin@123"`,
		`db_url = "mongodb://admin:pass@10.0.0.1:27017/prod"`,
		`accessKeyId: "LTAIabcdef1234567890"`,
		`Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmnopqrstuvwxyz`,
		`AKIAIOSFODNN7EXAMPLE`,
		`jdbc:mysql://db.internal.example.com:3306/appdb?user=root&password=s3cret`,
		`email: "admin@internal.example.com"`,
		`server: 192.168.1.100:8080`,
	}
	jsNoise := []string{
		`function initApp() { console.log("starting"); }`,
		`var config = { timeout: 3000, retries: 5 };`,
		`import { Component } from 'react';`,
		`export default class App extends Component {}`,
		`const styles = { color: '#333', fontSize: '14px' };`,
		`document.addEventListener('DOMContentLoaded', function() {});`,
		`if (window.location.href.indexOf('/api/') !== -1) { fetch('/api/data'); }`,
		`const routes = ['/home', '/about', '/contact', '/dashboard'];`,
		`let counter = 0; for (let i = 0; i < 100; i++) { counter += i; }`,
		`try { JSON.parse(responseText); } catch(e) { console.error(e); }`,
		`const headers = { 'Content-Type': 'application/json', 'Accept': '*/*' };`,
		`function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }`,
	}

	var lines []string
	targetLines := size / 60
	if targetLines < 1 {
		targetLines = 1
	}
	for len(lines) < targetLines {
		if rng.Float64() < matchRate && len(secrets) > 0 {
			lines = append(lines, secrets[rng.Intn(len(secrets))])
		} else {
			lines = append(lines, jsNoise[rng.Intn(len(jsNoise))])
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func buildProtonScanner() *Scanner {
	var rules []Rule
	for _, r := range sharedRules {
		req := &Request{Extensions: []string{"all"}}
		for _, p := range r.patterns {
			req.Operators.Extractors = append(req.Operators.Extractors, &operators.Extractor{
				Name: r.name, Type: "regex", Regex: []string{p},
			})
		}
		opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
		if err := req.Compile(opts); err != nil {
			panic(fmt.Sprintf("compile %s: %v", r.name, err))
		}
		rules = append(rules, Rule{
			ID: r.name, Name: r.name, Severity: "info",
			Requests: []*Request{req},
		})
	}
	return NewScanner(rules, nil)
}

func BenchmarkSprayExtractor(b *testing.B) {
	var extractors []*sprayExtractor
	for _, r := range sharedRules {
		extractors = append(extractors, newSprayExtractor(r.name, r.patterns))
	}

	scenarios := []struct {
		name      string
		bodySize  int
		matchRate float64
	}{
		{"1KB_5pct", 1024, 0.05},
		{"10KB_5pct", 10 * 1024, 0.05},
		{"100KB_5pct", 100 * 1024, 0.05},
		{"500KB_5pct", 500 * 1024, 0.05},
		{"100KB_30pct", 100 * 1024, 0.30},
	}

	for _, sc := range scenarios {
		rng := rand.New(rand.NewSource(42))
		body := string(generateJSBody(sc.bodySize, sc.matchRate, rng))

		b.Run(fmt.Sprintf("spray/%s/%drules", sc.name, len(extractors)), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, ext := range extractors {
					ext.Extract(body)
				}
			}
		})
	}
}

func BenchmarkProtonScanData(b *testing.B) {
	scanner := buildProtonScanner()

	scenarios := []struct {
		name      string
		bodySize  int
		matchRate float64
	}{
		{"1KB_5pct", 1024, 0.05},
		{"10KB_5pct", 10 * 1024, 0.05},
		{"100KB_5pct", 100 * 1024, 0.05},
		{"500KB_5pct", 500 * 1024, 0.05},
		{"100KB_30pct", 100 * 1024, 0.30},
	}

	for _, sc := range scenarios {
		rng := rand.New(rand.NewSource(42))
		body := generateJSBody(sc.bodySize, sc.matchRate, rng)

		b.Run(fmt.Sprintf("proton/%s/%drules", sc.name, len(sharedRules)), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, group := range scanner.Groups {
					scanner.scanData(body, "bench.js", group)
				}
			}
		})
	}
}

func BenchmarkProtonScanFile(b *testing.B) {
	scanner := buildProtonScanner()

	scenarios := []struct {
		name      string
		bodySize  int
		matchRate float64
	}{
		{"1KB_5pct", 1024, 0.05},
		{"100KB_5pct", 100 * 1024, 0.05},
		{"500KB_5pct", 500 * 1024, 0.05},
	}

	for _, sc := range scenarios {
		rng := rand.New(rand.NewSource(42))
		body := generateJSBody(sc.bodySize, sc.matchRate, rng)
		tmpDir := b.TempDir()
		os.WriteFile(filepath.Join(tmpDir, "response.js"), body, 0644)

		b.Run(fmt.Sprintf("proton_file/%s/%drules", sc.name, len(sharedRules)), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanDir(scanner, tmpDir, func(f Finding) {})
			}
		})
	}
}

func BenchmarkRegexEngine(b *testing.B) {
	var goRegexps []*regexp.Regexp
	var re2Regexps []*re2.Regexp
	for _, r := range sharedRules {
		for _, p := range r.patterns {
			if re, err := regexp.Compile(p); err == nil {
				goRegexps = append(goRegexps, re)
			}
			if re, err := re2.Compile(p); err == nil {
				re2Regexps = append(re2Regexps, re)
			}
		}
	}

	rng := rand.New(rand.NewSource(42))
	body := string(generateJSBody(100*1024, 0.05, rng))

	b.Run("go_stdlib_100KB", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		for i := 0; i < b.N; i++ {
			for _, re := range goRegexps {
				re.FindAllString(body, -1)
			}
		}
	})

	b.Run("re2_100KB", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		for i := 0; i < b.N; i++ {
			for _, re := range re2Regexps {
				re.FindAllString(body, -1)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// RE2 engine benchmarks
// ---------------------------------------------------------------------------

func generateCorpus(size int) string {
	var sb strings.Builder
	sb.Grow(size + 512)

	codeLines := []string{
		"func handleRequest(w http.ResponseWriter, r *http.Request) {",
		`    log.Printf("received request from %s", r.RemoteAddr)`,
		"    if r.Method != http.MethodPost {",
		`        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)`,
		"        return",
		"    }",
		`    data, err := io.ReadAll(r.Body)`,
		"    if err != nil {",
		`        http.Error(w, err.Error(), http.StatusBadRequest)`,
		"        return",
		"    }",
		`    result := processPayload(data)`,
		`    w.Header().Set("Content-Type", "application/json")`,
		"    json.NewEncoder(w).Encode(result)",
		"}",
		"",
		`var dbHost = "10.0.1.50"`,
		`var dbPort = 5432`,
		`var dbUser = "app_service"`,
		"",
		"type Config struct {",
		"    Host     string `json:\"host\"`",
		"    Port     int    `json:\"port\"`",
		"    APIKey   string `json:\"api_key\"`",
		"    LogLevel string `json:\"log_level\"`",
		"}",
	}

	secrets := []string{
		`server_ip = "192.168.1.100"`,
		`remote_addr: 10.20.30.40`,
		`contact: admin@example.com`,
		`api_key = "aK7bR9cD2eF4gH6iJ8kL0mN1oP3qR5s"`,
		`API-KEY: "xY9zW8vU7tS6rQ5pO4nM3lK2jI1hG0f"`,
		`apikey="ABCDEFGHIJ1234567890abcdef"`,
		`upstream 172.16.0.1:8080;`,
		`notification_email = "alerts@company.org"`,
		`ssh_host = "10.255.0.42"`,
		`api-key: Ts9kLmNpQrStUvWxYz0123456789AbCd`,
	}

	rng := rand.New(rand.NewSource(42))
	lineIdx := 0
	secretIdx := 0
	for sb.Len() < size {
		if lineIdx > 0 && lineIdx%15 == 0 {
			sb.WriteString(secrets[secretIdx%len(secrets)])
			sb.WriteByte('\n')
			secretIdx++
		}
		line := codeLines[lineIdx%len(codeLines)]
		sb.WriteString(line)
		pad := rng.Intn(20)
		for p := 0; p < pad; p++ {
			sb.WriteByte(' ')
		}
		sb.WriteByte('\n')
		lineIdx++
	}

	result := sb.String()
	if len(result) > size {
		result = result[:size]
	}
	return result
}

var (
	patSimple  = `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`
	patComplex = `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}`
	patMulti   = []string{
		`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`,
		`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}`,
		`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?\S+`,
		`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`,
	}
)

func BenchmarkMatchRegex(b *testing.B) {
	corpusSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
	}

	patterns := []struct {
		name    string
		pattern string
	}{
		{"simple", patSimple},
		{"complex", patComplex},
	}

	for _, cs := range corpusSizes {
		corpus := generateCorpus(cs.size)

		for _, pat := range patterns {
			b.Run(fmt.Sprintf("StdLib/%s/%s", pat.name, cs.name), func(b *testing.B) {
				re := regexp.MustCompile(pat.pattern)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = re.MatchString(corpus)
				}
			})

			b.Run(fmt.Sprintf("RE2/%s/%s", pat.name, cs.name), func(b *testing.B) {
				re := re2.MustCompile(pat.pattern)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = re.MatchString(corpus)
				}
			})
		}

		b.Run(fmt.Sprintf("StdLib/multi/%s", cs.name), func(b *testing.B) {
			compiled := make([]*regexp.Regexp, len(patMulti))
			for j, p := range patMulti {
				compiled[j] = regexp.MustCompile(p)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, re := range compiled {
					_ = re.MatchString(corpus)
				}
			}
		})

		b.Run(fmt.Sprintf("RE2/multi/%s", cs.name), func(b *testing.B) {
			compiled := make([]*re2.Regexp, len(patMulti))
			for j, p := range patMulti {
				compiled[j] = re2.MustCompile(p)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, re := range compiled {
					_ = re.MatchString(corpus)
				}
			}
		})
	}
}

func BenchmarkExtractRegex(b *testing.B) {
	corpusSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
	}

	patternSets := []struct {
		name     string
		patterns []string
	}{
		{"5patterns", patMulti},
		{"20patterns", func() []string {
			p := make([]string, 0, 20)
			for i := 0; i < 4; i++ {
				p = append(p, patMulti...)
			}
			return p
		}()},
	}

	for _, cs := range corpusSizes {
		corpus := generateCorpus(cs.size)

		for _, ps := range patternSets {
			b.Run(fmt.Sprintf("StdLib/%s/%s", ps.name, cs.name), func(b *testing.B) {
				compiled := make([]*regexp.Regexp, len(ps.patterns))
				for j, p := range ps.patterns {
					compiled[j] = regexp.MustCompile(p)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, re := range compiled {
						_ = re.FindAllStringSubmatch(corpus, -1)
					}
				}
			})

			b.Run(fmt.Sprintf("RE2/%s/%s", ps.name, cs.name), func(b *testing.B) {
				compiled := make([]*re2.Regexp, len(ps.patterns))
				for j, p := range ps.patterns {
					compiled[j] = re2.MustCompile(p)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, re := range compiled {
						_ = re.FindAllStringSubmatch(corpus, -1)
					}
				}
			})
		}
	}
}
