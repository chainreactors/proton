package file

import (
	"sort"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/stretchr/testify/require"
)

func TestExtractKeywords_Alternation(t *testing.T) {
	kws := extractKeywords(`(?i)(password|passwd|secret)\s*[:=]`)
	sort.Strings(kws)
	require.Equal(t, []string{"passwd", "password", "secret"}, kws)
}

func TestExtractKeywords_SingleWord(t *testing.T) {
	kws := extractKeywords(`api_key\s*=\s*\S+`)
	require.Len(t, kws, 1)
	require.Equal(t, "api", kws[0], "wordRe matches [a-zA-Z]{2,}, underscore splits the word")
}

func TestExtractKeywords_NoWord(t *testing.T) {
	kws := extractKeywords(`[0-9]+\.[0-9]+`)
	require.Nil(t, kws)
}

func TestExtractKeywords_CaseInsensitiveStripped(t *testing.T) {
	kws := extractKeywords(`(?i)Bearer\s+[a-zA-Z0-9]+`)
	require.Len(t, kws, 1)
	require.Equal(t, "bearer", kws[0])
}

func TestBuildACIndex_Basic(t *testing.T) {
	acCacheMu.Lock()
	acCache = map[*operators.Extractor]*acIndex{}
	acCacheMu.Unlock()

	ext := &operators.Extractor{
		Type: "regex",
		Regex: []string{
			`(?i)(password|passwd)\s*[:=]\s*\S+`,
			`(?i)api[_-]?key\s*[:=]\s*['"]?\S+`,
			`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`,
		},
	}
	require.NoError(t, ext.CompileExtractors())

	idx := buildACIndex(ext)
	require.NotNil(t, idx)
	require.True(t, len(idx.patterns) > 0, "should have extracted keywords")

	allMapped := make(map[int]bool)
	for _, patterns := range idx.keywordToPatterns {
		for _, pi := range patterns {
			allMapped[pi] = true
		}
	}
	require.True(t, len(allMapped) > 0, "keyword→pattern mapping should not be empty")
}

func TestBuildACIndex_Caching(t *testing.T) {
	acCacheMu.Lock()
	acCache = map[*operators.Extractor]*acIndex{}
	acCacheMu.Unlock()

	ext := &operators.Extractor{
		Type: "regex",
		Regex: []string{
			`(?i)(password|passwd)\s*[:=]\s*\S+`,
			`api_key\s*=\s*\S+`,
		},
	}
	require.NoError(t, ext.CompileExtractors())

	idx1 := buildACIndex(ext)
	idx2 := buildACIndex(ext)
	require.Same(t, idx1, idx2, "second call should return cached index")
}

func TestExtractRegexWithAC_Correctness(t *testing.T) {
	acCacheMu.Lock()
	acCache = map[*operators.Extractor]*acIndex{}
	acCacheMu.Unlock()

	patterns := []string{
		`(?i)(password|passwd)\s*[:=]\s*['"]?(\S+)`,
		`(?i)api[_-]?key\s*[:=]\s*['"]?(\S+)`,
		`(?i)(secret|token)\s*[:=]\s*['"]?(\S+)`,
		`(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)`,
		`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?(\S+)`,
		`(?i)(mysql|postgres|mongodb)://[^\s'"]+`,
		`(?i)private[_-]?key\s*[:=]\s*['"]?(\S+)`,
		`(?i)(ssh-rsa|ssh-ed25519)\s+\S+`,
		`(?i)authorization\s*[:=]\s*['"]?(\S+)`,
		`(?i)(github_token|gh_token)\s*[:=]\s*['"]?(\S+)`,
		`(?i)(slack_token|slack_webhook)\s*[:=]\s*['"]?(\S+)`,
	}

	ext := &operators.Extractor{
		Type:  "regex",
		Regex: patterns,
	}
	require.NoError(t, ext.CompileExtractors())

	corpus := `password = hunter2
api_key = "test_key_abc123"
token = "tok_xyz789"
bearer eyJhbGciOiJIUzI1NiJ9
nothing interesting here
`

	request := &Request{ID: "ac-test"}
	require.NoError(t, request.Compile(newTestOptions()))

	acResults := request.extractRegexWithAC(ext, corpus)

	extDirect := &operators.Extractor{
		Type:  "regex",
		Regex: patterns,
	}
	require.NoError(t, extDirect.CompileExtractors())
	directResults := request.extractRegexRE2(extDirect, corpus)

	acKeys := make([]string, 0, len(acResults))
	for k := range acResults {
		acKeys = append(acKeys, k)
	}
	sort.Strings(acKeys)

	directKeys := make([]string, 0, len(directResults))
	for k := range directResults {
		directKeys = append(directKeys, k)
	}
	sort.Strings(directKeys)

	require.True(t, len(acKeys) > 0, "AC path should find some results")
	for _, key := range acKeys {
		require.Contains(t, directResults, key,
			"every AC result must also be found by direct regex: %s", key)
	}
}

func TestExtractRegexWithAC_NoKeywords(t *testing.T) {
	acCacheMu.Lock()
	acCache = map[*operators.Extractor]*acIndex{}
	acCacheMu.Unlock()

	ext := &operators.Extractor{
		Type:  "regex",
		Regex: []string{`[0-9]+`},
	}
	require.NoError(t, ext.CompileExtractors())

	request := &Request{ID: "ac-fallback"}
	require.NoError(t, request.Compile(newTestOptions()))

	results := request.extractRegexWithAC(ext, "number 42 here")
	require.NotNil(t, results)
	require.Contains(t, results, "42")
}
