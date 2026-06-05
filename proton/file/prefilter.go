package file

import (
	"bytes"
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/utils/ahocorasick"
)

// linePrefilter uses literal substrings extracted from regex patterns to
// quickly skip lines that cannot possibly match any extractor or matcher.
// This avoids the cost of full regex evaluation on every line.
type linePrefilter struct {
	literals           [][]byte
	lowercaseLiterals  [][]byte
	hasCaseInsensitive bool
	disabled           bool // true when no literals could be extracted
	ac                 *ahocorasick.Automaton
	useAC              bool                     // true when ac should be used
}

// buildPrefilter inspects all extractors and matchers in the compiled operators
// and builds a prefilter from literal fragments found in their patterns.
func buildPrefilter(ops *operators.Operators) *linePrefilter {
	if ops == nil {
		return nil
	}

	var allLiterals []string
	var hasCaseInsensitive bool

	// Collect literals from regex extractors.
	for _, ext := range ops.Extractors {
		if ext.GetType() != operators.RegexExtractor {
			continue
		}
		for _, pattern := range ext.Regex {
			lits := extractLiterals(pattern)
			if len(lits) == 0 {
				// This extractor has no extractable literals — we can't
				// safely skip any line because it might match.
				return &linePrefilter{disabled: true}
			}
			allLiterals = append(allLiterals, lits...)
			if strings.HasPrefix(pattern, "(?i)") {
				hasCaseInsensitive = true
			}
		}
	}

	// Collect literals from matchers.
	for _, m := range ops.Matchers {
		switch m.GetType() {
		case operators.RegexMatcher:
			for _, pattern := range m.Regex {
				lits := extractLiterals(pattern)
				if len(lits) == 0 {
					return &linePrefilter{disabled: true}
				}
				allLiterals = append(allLiterals, lits...)
				if strings.HasPrefix(pattern, "(?i)") || m.CaseInsensitive {
					hasCaseInsensitive = true
				}
			}
		case operators.WordsMatcher:
			for _, word := range m.Words {
				if len(word) >= 3 {
					allLiterals = append(allLiterals, word)
				} else {
					// Word too short to be a useful filter.
					return &linePrefilter{disabled: true}
				}
			}
			if m.CaseInsensitive {
				hasCaseInsensitive = true
			}
		case operators.DSLMatcher:
			// DSL matchers can match on arbitrary expressions; we can't
			// extract literals from them, so disable the prefilter.
			return &linePrefilter{disabled: true}
		}
	}

	if len(allLiterals) == 0 {
		return &linePrefilter{disabled: true}
	}

	f := &linePrefilter{
		literals:           make([][]byte, len(allLiterals)),
		hasCaseInsensitive: hasCaseInsensitive,
	}
	for i, lit := range allLiterals {
		f.literals[i] = []byte(lit)
	}
	if hasCaseInsensitive {
		f.lowercaseLiterals = make([][]byte, len(allLiterals))
		for i, lit := range allLiterals {
			f.lowercaseLiterals[i] = []byte(strings.ToLower(lit))
		}
	}

	// Build Aho-Corasick automaton when there are many literals.
	if len(allLiterals) > 10 {
		acPatterns := make([]string, len(allLiterals))
		for i, lit := range allLiterals {
			if hasCaseInsensitive {
				acPatterns[i] = strings.ToLower(lit)
			} else {
				acPatterns[i] = lit
			}
		}
		ac, err := ahocorasick.NewBuilder().
			AddStrings(acPatterns).
			Build()
		if err == nil {
			f.ac = ac
			f.useAC = true
		}
	}

	return f
}

func extractLiterals(pattern string) []string {
	return ahocorasick.ExtractLiterals(pattern)
}

// mayMatch returns true if the line might match any of the prefilter's
// literal patterns. When it returns false, the caller can safely skip
// the line.
func (f *linePrefilter) mayMatch(line []byte) bool {
	if f == nil || f.disabled {
		return true
	}
	if f.useAC {
		if f.hasCaseInsensitive {
			return f.ac.IsMatch(asciiLowerBytes(line))
		}
		return f.ac.IsMatch(line)
	}
	if f.hasCaseInsensitive {
		for _, lit := range f.lowercaseLiterals {
			if containsFoldASCII(line, lit) {
				return true
			}
		}
		return false
	}
	for _, lit := range f.literals {
		if bytes.Contains(line, lit) {
			return true
		}
	}
	return false
}

func asciiLowerBytes(s []byte) []byte {
	out := make([]byte, len(s))
	for i, b := range s {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		} else {
			out[i] = b
		}
	}
	return out
}

// containsFoldASCII performs a case-insensitive substring search without
// allocating a lowercased copy of s.
func containsFoldASCII(s, substr []byte) bool {
	n := len(substr)
	if n == 0 {
		return true
	}
	if n > len(s) {
		return false
	}
	for i := 0; i <= len(s)-n; i++ {
		if equalFoldASCII(s[i:i+n], substr) {
			return true
		}
	}
	return false
}

// equalFoldASCII compares two byte slices of equal length for ASCII
// case-insensitive equality without any allocation.
func equalFoldASCII(a, b []byte) bool {
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
