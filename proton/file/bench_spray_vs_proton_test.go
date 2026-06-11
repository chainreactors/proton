//go:build go1.18
// +build go1.18

package file

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	re2 "github.com/wasilibs/go-re2"
)

// sprayExtractor mimics spray's parsers.Extractor: compile Go stdlib regex,
// run FindAllString on the entire body for every pattern.
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

// --- shared rule definitions (subset matching spray's extract.yaml) ---

type ruleSpec struct {
	name     string
	patterns []string
}

var sharedRules = []ruleSpec{
	{"jwt", []string{
		`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}`,
	}},
	{"mail", []string{
		`[A-Za-z0-9_.]+@[A-Za-z0-9_.-]+\.[A-Za-z]{2,8}`,
	}},
	{"phone", []string{
		`(\+?0?86-?)?1[3-9]\d{9}`,
	}},
	{"ip", []string{
		`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`,
	}},
	{"internal-ip", []string{
		`[^0-9]((127\.0\.0\.1)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))`,
	}},
	{"password", []string{
		`(?i)(pass|pwd|passwd|password)[\s="':]+[A-Za-z0-9!@#$%^?.*&]{3,20}["']`,
	}},
	{"username", []string{
		`(?i)(user|name|username)[\s="':]+[A-Za-z0-9!@%.]{3,20}[\s"']`,
	}},
	{"aws-ak", []string{
		`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[a-zA-Z0-9]{16}`,
	}},
	{"oss", []string{
		`(?i)access[_-]?key[_-]?id\s*[:=]\s*["']?([A-Za-z0-9/+=]{16,})["']?`,
		`(?i)access[_-]?key[_-]?secret\s*[:=]\s*["']?([A-Za-z0-9/+=]{16,})["']?`,
	}},
	{"rsa-key", []string{
		`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`,
	}},
	{"jdbc", []string{
		`jdbc:[a-z0-9]+://[a-z0-9.\-_:;=/@?,&]+`,
	}},
	{"github-token", []string{
		`[a-z0-9_-]*:[a-z0-9_-]+@github\.com[^\s"']*`,
	}},
	{"bearer", []string{
		`(?i)["':]?\s*[Bb]earer\s+([A-Za-z0-9_.-]{20,})`,
	}},
	{"api-key", []string{
		`(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,64})["']?`,
		`(?i)(secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,64})["']?`,
		`(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_.-]{16,})["']?`,
	}},
	{"aliyun-ak", []string{
		`LTAI[A-Za-z0-9]{12,20}`,
	}},
	{"tencent-cloud", []string{
		`AKID[A-Za-z0-9]{13,20}`,
	}},
	{"github-pat", []string{
		`ghp_[A-Za-z0-9]{36}`,
		`gho_[A-Za-z0-9]{36}`,
		`ghu_[A-Za-z0-9]{36}`,
		`ghs_[A-Za-z0-9]{36}`,
		`github_pat_[A-Za-z0-9_]{82}`,
	}},
	{"stripe", []string{
		`[sr]k_(live|test)_[0-9a-zA-Z]{24,}`,
		`pk_(live|test)_[0-9a-zA-Z]{24,}`,
	}},
	{"google-api", []string{
		`AIza[0-9A-Za-z_-]{35}`,
	}},
	{"slack-webhook", []string{
		`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`,
		`xox[bpas]-[0-9]+-[0-9]+-[a-zA-Z0-9]+`,
	}},
	{"db-connection", []string{
		`mongodb(\+srv)?://[^\s"'<>]{10,}`,
		`redis://[^\s"'<>]{5,}`,
		`mysql://[^\s"'<>]{10,}`,
		`postgres(ql)?://[^\s"'<>]{10,}`,
	}},
}

// --- test data generators ---

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

// --- build proton scanner from shared rules ---

func buildProtonScanner() *Scanner {
	var rules []Rule
	for _, r := range sharedRules {
		req := &Request{
			Extensions: []string{"all"},
		}
		for _, p := range r.patterns {
			req.Operators.Extractors = append(req.Operators.Extractors, &operators.Extractor{
				Name:  r.name,
				Type:  "regex",
				Regex: []string{p},
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

// --- spray-style benchmark (Go stdlib regex, full body, no prefilter) ---

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

// --- proton scanData benchmark (in-memory, no filesystem I/O) ---

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

// --- proton via Scan (with filesystem) benchmark ---

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

// --- raw regex engine comparison ---

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
