package file

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/stretchr/testify/require"
)

func TestExtractLiterals_SimpleLiteral(t *testing.T) {
	lits := extractLiterals(`PRIVATE KEY`)
	require.Equal(t, []string{"PRIVATE KEY"}, lits)
}

func TestExtractLiterals_WithMetachars(t *testing.T) {
	lits := extractLiterals(`api_key\s*=\s*\S+`)
	require.Equal(t, []string{"api_key"}, lits)
}

func TestExtractLiterals_Alternation(t *testing.T) {
	lits := extractLiterals(`(password|passwd|secret)`)
	require.ElementsMatch(t, []string{"password", "passwd", "secret"}, lits)
}

func TestExtractLiterals_CaseInsensitivePrefix(t *testing.T) {
	lits := extractLiterals(`(?i)PRIVATE KEY`)
	require.Equal(t, []string{"PRIVATE KEY"}, lits)
}

func TestExtractLiterals_TooShort(t *testing.T) {
	lits := extractLiterals(`\d+`)
	require.Nil(t, lits, "no extractable literal >= 3 chars")
}

func TestExtractLiterals_EscapedMeta(t *testing.T) {
	lits := extractLiterals(`BEGIN\$END`)
	require.NotNil(t, lits)
	require.True(t, len(lits[0]) >= 3)
}

func TestExtractLiterals_AlternationWithShort(t *testing.T) {
	lits := extractLiterals(`(key|password|ab)`)
	require.Equal(t, []string{"key", "password"}, lits,
		"'key' (3 chars) and 'password' pass the >= 3 && QuoteMeta filter; 'ab' (2 chars) is excluded")
}

func TestBuildPrefilter_FromRegex(t *testing.T) {
	ops := &operators.Operators{
		Extractors: []*operators.Extractor{{
			Type:  "regex",
			Regex: []string{`PRIVATE KEY`},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.NotNil(t, pf)
	require.False(t, pf.disabled)
	require.Len(t, pf.literals, 1)
	require.Equal(t, []byte("PRIVATE KEY"), pf.literals[0])
}

func TestBuildPrefilter_FromWords(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:  "word",
			Words: []string{"password", "secret"},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.NotNil(t, pf)
	require.False(t, pf.disabled)
	require.Len(t, pf.literals, 2)
}

func TestBuildPrefilter_ShortWordDisables(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:  "word",
			Words: []string{"ok"},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.True(t, pf.disabled, "word < 3 chars should disable prefilter")
}

func TestBuildPrefilter_DSLDisables(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type: "dsl",
			DSL:  []string{`len(raw) > 100`},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.True(t, pf.disabled, "DSL matcher should disable prefilter")
}

func TestBuildPrefilter_ACThreshold(t *testing.T) {
	var words []string
	for i := 0; i < 15; i++ {
		words = append(words, strings.Repeat("word", 1)+string(rune('a'+i))+"xx")
	}
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:  "word",
			Words: words,
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.False(t, pf.disabled)
	require.True(t, pf.useAC, ">10 literals should enable AC automaton")
	require.NotNil(t, pf.ac)
}

func TestBuildPrefilter_NoACBelowThreshold(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:  "word",
			Words: []string{"alpha", "beta", "gamma"},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.False(t, pf.disabled)
	require.False(t, pf.useAC, "<=10 literals should not use AC")
}

func TestBuildPrefilter_CaseInsensitive(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:            "word",
			Words:           []string{"Password"},
			CaseInsensitive: true,
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.False(t, pf.disabled)
	require.True(t, pf.hasCaseInsensitive)
	require.NotNil(t, pf.lowercaseLiterals)
}

func TestBuildPrefilter_NilOps(t *testing.T) {
	pf := buildPrefilter(nil)
	require.Nil(t, pf)
}

func TestBuildPrefilter_NoExtractableLiteral(t *testing.T) {
	ops := &operators.Operators{
		Extractors: []*operators.Extractor{{
			Type:  "regex",
			Regex: []string{`\d+`},
		}},
	}
	require.NoError(t, ops.Compile())

	pf := buildPrefilter(ops)
	require.True(t, pf.disabled, "regex with no extractable literal should disable prefilter")
}

func TestMayMatch_NilPrefilter(t *testing.T) {
	var pf *linePrefilter
	require.True(t, pf.mayMatch([]byte("anything")), "nil prefilter should always return true")
}

func TestMayMatch_DisabledPrefilter(t *testing.T) {
	pf := &linePrefilter{disabled: true}
	require.True(t, pf.mayMatch([]byte("anything")), "disabled prefilter should always return true")
}

func TestMayMatch_Hit(t *testing.T) {
	pf := &linePrefilter{
		literals: [][]byte{[]byte("secret")},
	}
	require.True(t, pf.mayMatch([]byte("this has a secret in it")))
}

func TestMayMatch_Miss(t *testing.T) {
	pf := &linePrefilter{
		literals: [][]byte{[]byte("secret")},
	}
	require.False(t, pf.mayMatch([]byte("nothing interesting here")))
}

func TestMayMatch_NoFalseNegative(t *testing.T) {
	ops := &operators.Operators{
		Matchers: []*operators.Matcher{{
			Type:  "word",
			Words: []string{"PRIVATE KEY", "password", "secret_token"},
		}},
	}
	require.NoError(t, ops.Compile())
	pf := buildPrefilter(ops)

	lines := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"password = hunter2",
		"secret_token=abc123",
		"PRIVATE KEY embedded",
	}
	for _, line := range lines {
		require.True(t, pf.mayMatch([]byte(line)),
			"prefilter must not produce false negatives for: %s", line)
	}
}

func TestMayMatch_CaseInsensitive(t *testing.T) {
	pf := &linePrefilter{
		literals:           [][]byte{[]byte("Secret")},
		lowercaseLiterals:  [][]byte{[]byte("secret")},
		hasCaseInsensitive: true,
	}
	require.True(t, pf.mayMatch([]byte("this has a SECRET in it")))
	require.True(t, pf.mayMatch([]byte("this has a secret in it")))
	require.True(t, pf.mayMatch([]byte("this has a SeCrEt in it")))
	require.False(t, pf.mayMatch([]byte("no match here")))
}

func TestContainsFoldASCII_Basic(t *testing.T) {
	require.True(t, containsFoldASCII([]byte("Hello World"), []byte("hello")))
	require.True(t, containsFoldASCII([]byte("HELLO WORLD"), []byte("hello")))
	require.True(t, containsFoldASCII([]byte("hello world"), []byte("hello")))
	require.False(t, containsFoldASCII([]byte("hi world"), []byte("hello")))
}

func TestContainsFoldASCII_EmptySubstr(t *testing.T) {
	require.True(t, containsFoldASCII([]byte("anything"), []byte("")))
}

func TestContainsFoldASCII_SubstrLongerThanS(t *testing.T) {
	require.False(t, containsFoldASCII([]byte("hi"), []byte("hello")))
}

func TestContainsFoldASCII_Exact(t *testing.T) {
	require.True(t, containsFoldASCII([]byte("ABC"), []byte("abc")))
}

var literal = []byte("PRIVATE KEY")

func buildLines(n int) [][]byte {
	lines := make([][]byte, n)
	for i := range lines {
		if i%100 == 0 { // 1% of lines contain the literal
			lines[i] = []byte(strings.Repeat("x", 34) + "PRIVATE KEY" + strings.Repeat("x", 35))
		} else {
			lines[i] = []byte(strings.Repeat("abcdefgh", 10)) // 80 chars
		}
	}
	return lines
}

func BenchmarkPrefilter(b *testing.B) {
	missLine := []byte(strings.Repeat("abcdefgh", 10))
	hitLine := []byte(strings.Repeat("x", 34) + "PRIVATE KEY" + strings.Repeat("x", 35))

	b.Run("MayMatch/miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bytes.Contains(missLine, literal)
		}
	})

	b.Run("MayMatch/hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bytes.Contains(hitLine, literal)
		}
	})
}

func BenchmarkScanLine(b *testing.B) {
	for _, lineCount := range []int{12, 1250} { // ~1KB (12*80), ~100KB (1250*80)
		label := fmt.Sprintf("%dKB", lineCount*80/1024)
		if lineCount*80 < 1024 {
			label = "1KB"
		}
		lines := buildLines(lineCount)

		b.Run(fmt.Sprintf("NoPrefilter/%s", label), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					m := make(map[string]interface{}, 4)
					m["raw"] = string(line)
					m["type"] = "file"
					m["matched"] = false
					m["length"] = len(line)
					_ = m
				}
			}
		})

		b.Run(fmt.Sprintf("WithPrefilter/%s", label), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					if !bytes.Contains(line, literal) {
						continue
					}
					m := make(map[string]interface{}, 4)
					m["raw"] = string(line)
					m["type"] = "file"
					m["matched"] = true
					m["length"] = len(line)
					_ = m
				}
			}
		})
	}
}
