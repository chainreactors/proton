//go:build go1.18
// +build go1.18

package file

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	re2regexp "github.com/wasilibs/go-re2"
)

// generateCorpus produces a realistic code corpus of approximately the given
// size, interspersed with IP addresses, emails, and API-key-like strings.
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
		"// Database configuration",
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

	// Secrets and identifiers to inject periodically
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
		// Inject a secret every ~15 lines
		if lineIdx > 0 && lineIdx%15 == 0 {
			sb.WriteString(secrets[secretIdx%len(secrets)])
			sb.WriteByte('\n')
			secretIdx++
		}
		line := codeLines[lineIdx%len(codeLines)]
		sb.WriteString(line)
		// Pad to variable width to simulate real code
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

// Regex patterns used in benchmarks
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
				re := re2regexp.MustCompile(pat.pattern)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = re.MatchString(corpus)
				}
			})
		}

		// Multi-pattern: run 5 patterns sequentially on the same corpus
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
			compiled := make([]*re2regexp.Regexp, len(patMulti))
			for j, p := range patMulti {
				compiled[j] = re2regexp.MustCompile(p)
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
			// Repeat the 5 base patterns 4 times for 20 total
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
				compiled := make([]*re2regexp.Regexp, len(ps.patterns))
				for j, p := range ps.patterns {
					compiled[j] = re2regexp.MustCompile(p)
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
