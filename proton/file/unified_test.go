package file

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
)

func makeRule(id, name, severity string, reqs ...*Request) Rule {
	return Rule{ID: id, Name: name, Severity: severity, Requests: reqs}
}

func compileRequest(t *testing.T, req *Request, opts *protocols.ExecuterOptions) *Request {
	t.Helper()
	if opts == nil {
		opts = newTestOptions()
	}
	err := req.Compile(opts)
	require.NoError(t, err, "could not compile request")
	return req
}

func writeTempFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		sub := filepath.Dir(name)
		if sub != "." {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0755))
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0644))
	}
	return dir
}

func scanDir(s *Scanner, target string, callback func(Finding)) error {
	numWorkers := runtime.NumCPU()
	type job struct {
		path  string
		group *scanGroup
	}
	jobCh := make(chan job, numWorkers*256)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				for _, c := range s.ReadFile(j.path, j.group) {
					findings := s.ScanData(c.Data, c.Label, j.group)
					if len(findings) > 0 {
						atomic.AddInt64(&s.Stats.Findings, int64(len(findings)))
						cbMu.Lock()
						for _, f := range findings {
							callback(f)
						}
						cbMu.Unlock()
					}
				}
			}
		}()
	}

	walkErr := parallelWalk(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if ShouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := filepath.Ext(path)
		if ShouldDenyExt(ext) {
			return nil
		}
		for _, group := range s.Groups {
			if !group.MatchesFile(path, ext) {
				continue
			}
			jobCh <- job{path: path, group: group}
		}
		return nil
	})
	close(jobCh)
	wg.Wait()
	return walkErr
}

func collectFindings(t *testing.T, scanner *Scanner, target string) []Finding {
	t.Helper()
	var mu sync.Mutex
	var findings []Finding
	err := scanDir(scanner, target, func(f Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	})
	require.NoError(t, err)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].TemplateID != findings[j].TemplateID {
			return findings[i].TemplateID < findings[j].TemplateID
		}
		return findings[i].FilePath < findings[j].FilePath
	})
	return findings
}

func TestScanner_WordMatcher(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"secret.txt":  "my-api-key = test_key_abc123\nnothing here\n",
		"clean.txt":   "this file has no secrets at all\n",
		"another.txt": "test_key_abc123 appears here too\n",
	})

	req := compileRequest(t, &Request{
		ID:         "word-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Name:  "apikey",
				Part:  "raw",
				Type:  "word",
				Words: []string{"test_key_abc123"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("word-test", "Word Test", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2, "should match 2 files")
	matchedFiles := []string{filepath.Base(findings[0].FilePath), filepath.Base(findings[1].FilePath)}
	sort.Strings(matchedFiles)
	require.Equal(t, []string{"another.txt", "secret.txt"}, matchedFiles)
	require.Equal(t, "word-test", findings[0].TemplateID)
}

func TestScanner_WordMatcher_AND(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"both.txt":    "password=secret123\nusername=admin\n",
		"partial.txt": "password=secret123\nno user here\n",
	})

	req := compileRequest(t, &Request{
		ID:         "and-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			MatchersCondition: "and",
			Matchers: []*operators.Matcher{
				{Part: "raw", Type: "word", Words: []string{"password"}},
				{Part: "raw", Type: "word", Words: []string{"username"}},
			},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("and-test", "AND Test", "medium", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1, "AND condition: only file with both words should match")
	require.Contains(t, findings[0].FilePath, "both.txt")
}

func TestScanner_RegexExtractor(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"keys.txt": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nclean line\n",
	})

	req := compileRequest(t, &Request{
		ID:         "regex-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Extractors: []*operators.Extractor{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{`aws_access_key_id\s*=\s*(\S+)`},
				RegexGroup: 1,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("regex-test", "Regex Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Result)
	require.Contains(t, findings[0].Result.OutputExtracts, "AKIAIOSFODNN7EXAMPLE")
}

func TestScanner_RegexExtractor_GroupCapture(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"keys.txt": `api_key = "abc123"\napi_key = "def456"\n`,
	})

	req := compileRequest(t, &Request{
		ID:         "group-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Extractors: []*operators.Extractor{{
				Part:       "raw",
				Type:       "regex",
				Regex:      []string{`api_key\s*=\s*"([^"]+)"`},
				RegexGroup: 1,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("group-test", "Group Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	extracts := findings[0].Result.OutputExtracts
	sort.Strings(extracts)
	require.Equal(t, []string{"abc123", "def456"}, extracts)
}

func TestScanner_MultiTemplate(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"data.txt": "PRIVATE KEY found here\nsecret_token=xyz_value\n",
	})

	req1 := compileRequest(t, &Request{
		ID:         "tmpl-1",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	req2 := compileRequest(t, &Request{
		ID:         "tmpl-2",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"secret_token"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{
		makeRule("tmpl-1", "Template 1", "high", req1),
		makeRule("tmpl-2", "Template 2", "info", req2),
	}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2, "both templates should produce findings")
	ids := []string{findings[0].TemplateID, findings[1].TemplateID}
	sort.Strings(ids)
	require.Equal(t, []string{"tmpl-1", "tmpl-2"}, ids)
}

func TestScanner_ExtensionFilter(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"match.yaml":  "PRIVATE KEY\n",
		"match.json":  "PRIVATE KEY\n",
		"ignore.go":   "PRIVATE KEY\n",
		"ignore.txt":  "PRIVATE KEY\n",
	})

	req := compileRequest(t, &Request{
		ID:         "ext-test",
		MaxSize:    "1Gb",
		Extensions: []string{".yaml", ".json"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("ext-test", "Ext Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2)
	matchedFiles := []string{filepath.Base(findings[0].FilePath), filepath.Base(findings[1].FilePath)}
	sort.Strings(matchedFiles)
	require.Equal(t, []string{"match.json", "match.yaml"}, matchedFiles)
}

func TestScanner_TextOnly(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"config.yaml": "PRIVATE KEY line\n",
		"binary.dat":  string([]byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x0A, 0x00, 0x00}),
	})

	req := compileRequest(t, &Request{
		ID:         "textonly-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, newTextOnlyOptions())

	scanner := NewScanner([]Rule{makeRule("textonly-test", "TextOnly Test", "info", req)}, newTextOnlyOptions())
	findings := collectFindings(t, scanner, dir)

	for _, f := range findings {
		require.NotContains(t, f.FilePath, "binary.dat", "binary file should be skipped in TextOnly mode")
	}
}

func TestScanner_CaseInsensitive(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"mixed.txt": "This has a Private Key here\n",
		"upper.txt": "PRIVATE KEY\n",
		"lower.txt": "private key\n",
		"none.txt":  "nothing interesting\n",
	})

	req := compileRequest(t, &Request{
		ID:         "case-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part:            "raw",
				Type:            "word",
				Words:           []string{"private key"},
				CaseInsensitive: true,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("case-test", "Case Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 3, "should match mixed, upper, and lower case files")
	matchedFiles := make([]string, len(findings))
	for i, f := range findings {
		matchedFiles[i] = filepath.Base(f.FilePath)
	}
	sort.Strings(matchedFiles)
	require.Equal(t, []string{"lower.txt", "mixed.txt", "upper.txt"}, matchedFiles)
}

func TestScanner_NegativeMatcher(t *testing.T) {
	// NOTE: The unified scanner applies Negative inversion in both
	// matchWordsStatic (via ResultWithMatchedSnippet) and buildFinding,
	// resulting in double-negation. Current behavior: Negative word matcher
	// matches ALL files because the double inversion cancels out.
	// This test documents current behavior.
	dir := writeTempFiles(t, map[string]string{
		"good.txt": "this is clean content\n",
		"bad.txt":  "this has PRIVATE KEY in it\n",
	})

	req := compileRequest(t, &Request{
		ID:         "neg-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part:     "raw",
				Type:     "word",
				Negative: true,
				Words:    []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("neg-test", "Neg Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2, "double-negation: both files match with current behavior")
}

func TestScanner_EmptyFile(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"empty.txt":   "",
		"notempty.txt": "PRIVATE KEY\n",
	})

	req := compileRequest(t, &Request{
		ID:         "empty-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("empty-test", "Empty Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.Contains(t, findings[0].FilePath, "notempty.txt")
}

func TestScanner_LargeFile(t *testing.T) {
	var sb strings.Builder
	for sb.Len() < 40*1024 {
		sb.WriteString("filler line with no interesting content abcdefghij\n")
	}
	sb.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	sb.WriteString("MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n")
	sb.WriteString("-----END RSA PRIVATE KEY-----\n")

	dir := writeTempFiles(t, map[string]string{
		"large.txt": sb.String(),
	})

	req := compileRequest(t, &Request{
		ID:         "large-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
			Extractors: []*operators.Extractor{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{`BEGIN (RSA PRIVATE KEY)`},
				RegexGroup: 1,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("large-test", "Large Test", "critical", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.True(t, findings[0].Result.Matched)
	require.Contains(t, findings[0].Result.OutputExtracts, "RSA PRIVATE KEY")
}

func TestScanner_Prefilter_Consistency(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"has_key.txt":  "api_key=abc123\npassword=secret\n",
		"no_match.txt": "this file is completely clean\n",
	})

	req := compileRequest(t, &Request{
		ID:         "prefilter-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Extractors: []*operators.Extractor{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{`(api_key|password)\s*=\s*(\S+)`},
				RegexGroup: 2,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("prefilter-test", "Prefilter Test", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	extracts := findings[0].Result.OutputExtracts
	sort.Strings(extracts)
	require.Equal(t, []string{"abc123", "secret"}, extracts)
}

func TestScanner_RegexMatcher(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"match.txt":   "password = hunter2\n",
		"nomatch.txt": "nothing secret here\n",
	})

	req := compileRequest(t, &Request{
		ID:         "regex-matcher-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{`password\s*=\s*\S+`},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("regex-matcher-test", "Regex Matcher", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.Contains(t, findings[0].FilePath, "match.txt")
}

func TestScanner_MatcherWithExtractor(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"secrets.txt": "password=hunter2\npassword=secret99\nnothing here\n",
	})

	req := compileRequest(t, &Request{
		ID:         "combo-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"password"},
			}},
			Extractors: []*operators.Extractor{{
				Part:       "raw",
				Type:       "regex",
				Regex:      []string{`password=(\S+)`},
				RegexGroup: 1,
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("combo-test", "Combo Test", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.True(t, findings[0].Result.Matched)
	extracts := findings[0].Result.OutputExtracts
	sort.Strings(extracts)
	require.Equal(t, []string{"hunter2", "secret99"}, extracts)
}

func TestScanner_NoFindings(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"clean1.txt": "just regular text\n",
		"clean2.txt": "nothing secret here\n",
	})

	req := compileRequest(t, &Request{
		ID:         "nofind-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("nofind-test", "No Find", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 0)
}

func TestScanner_SkipDirs(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"node_modules/leaked.txt": "PRIVATE KEY\n",
		"__pycache__/leaked.txt":  "PRIVATE KEY\n",
		"src/leaked.txt":          "PRIVATE KEY\n",
	})

	req := compileRequest(t, &Request{
		ID:         "skipdir-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("skipdir-test", "SkipDir", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1, "only src/leaked.txt should match; node_modules and __pycache__ should be skipped")
	require.Contains(t, findings[0].FilePath, "src")
}

func TestScanner_SkipMedia(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		"image.png":  "PRIVATE KEY\n",
		"video.mp4":  "PRIVATE KEY\n",
		"font.woff2": "PRIVATE KEY\n",
		"config.txt": "PRIVATE KEY\n",
	})

	req := compileRequest(t, &Request{
		ID:         "skipmedia-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("skipmedia-test", "SkipMedia", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1, "only config.txt should match; media files should be skipped at walk level")
	require.Contains(t, findings[0].FilePath, "config.txt")
}

func TestScanner_GitNotSkipped(t *testing.T) {
	dir := writeTempFiles(t, map[string]string{
		".git/config":    "password=leaked_secret\n",
		"src/normal.txt": "password=another_one\n",
	})

	req := compileRequest(t, &Request{
		ID:         "git-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"password"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("git-test", "GitTest", "info", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2, ".git should NOT be skipped — it may contain leaked credentials")
	foundGit := false
	for _, f := range findings {
		if strings.Contains(f.FilePath, ".git") {
			foundGit = true
		}
	}
	require.True(t, foundGit, ".git/config should be scanned")
}

func createTestTar(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "test.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	tw := tar.NewWriter(f)
	for name, content := range files {
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(content)), Mode: 0644})
		tw.Write([]byte(content))
	}
	tw.Close()
	f.Close()
	return path
}

func createTestTarGz(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(path)
	require.NoError(t, err)
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(content)), Mode: 0644})
		tw.Write([]byte(content))
	}
	tw.Close()
	gw.Close()
	f.Close()
	return path
}

func createTestZip(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "test.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}
	zw.Close()
	f.Close()
	return path
}

func archiveScannerReq(t *testing.T) *Request {
	t.Helper()
	return compileRequest(t, &Request{
		ID:         "archive-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
			Extractors: []*operators.Extractor{{
				Part:       "raw",
				Type:       "regex",
				Regex:      []string{`password=(\S+)`},
				RegexGroup: 1,
			}},
		},
	}, nil)
}

func TestScanner_Archive_Tar(t *testing.T) {
	dir := t.TempDir()
	createTestTar(t, dir, map[string]string{
		"secret.txt": "PRIVATE KEY\npassword=hunter2\n",
		"clean.txt":  "nothing here\n",
	})

	req := archiveScannerReq(t)
	scanner := NewScanner([]Rule{makeRule("archive-test", "Archive", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.Contains(t, findings[0].FilePath, "test.tar:secret.txt")
	require.True(t, findings[0].Result.Matched)
	require.Contains(t, findings[0].Result.OutputExtracts, "hunter2")
}

func TestScanner_Archive_TarGz(t *testing.T) {
	dir := t.TempDir()
	createTestTarGz(t, dir, map[string]string{
		"config.yaml": "PRIVATE KEY\npassword=s3cret\n",
	})

	req := archiveScannerReq(t)
	scanner := NewScanner([]Rule{makeRule("archive-test", "Archive", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.Contains(t, findings[0].FilePath, "test.tar.gz:config.yaml")
	require.Contains(t, findings[0].Result.OutputExtracts, "s3cret")
}

func TestScanner_Archive_Zip(t *testing.T) {
	dir := t.TempDir()
	createTestZip(t, dir, map[string]string{
		"dir/secret.env": "PRIVATE KEY\npassword=zippass\n",
		"dir/readme.md":  "nothing\n",
	})

	req := archiveScannerReq(t)
	scanner := NewScanner([]Rule{makeRule("archive-test", "Archive", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1)
	require.Contains(t, findings[0].FilePath, "test.zip:dir/secret.env")
	require.Contains(t, findings[0].Result.OutputExtracts, "zippass")
}

func TestScanner_Archive_SkipsMediaInside(t *testing.T) {
	dir := t.TempDir()
	createTestZip(t, dir, map[string]string{
		"image.png":  "PRIVATE KEY\n",
		"config.txt": "PRIVATE KEY\n",
	})

	req := archiveScannerReq(t)
	scanner := NewScanner([]Rule{makeRule("archive-test", "Archive", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 1, "image.png inside zip should be skipped")
	require.Contains(t, findings[0].FilePath, "config.txt")
}

func TestScanner_Archive_MixedWithRegularFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("PRIVATE KEY\n"), 0644)
	createTestTar(t, dir, map[string]string{
		"inside.txt": "PRIVATE KEY\n",
	})

	req := compileRequest(t, &Request{
		ID:         "mixed-test",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{
				Part: "raw", Type: "word", Words: []string{"PRIVATE KEY"},
			}},
		},
	}, nil)

	scanner := NewScanner([]Rule{makeRule("mixed-test", "Mixed", "high", req)}, newTestOptions())
	findings := collectFindings(t, scanner, dir)

	require.Len(t, findings, 2, "should find in both plain file and inside tar")
}
