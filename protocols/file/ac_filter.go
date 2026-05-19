package file

import (
	"regexp"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/operators"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

var wordRe = regexp.MustCompile(`[a-zA-Z]{2,}`)

type acIndex struct {
	ac       ahocorasick.AhoCorasick
	patterns []string
	// keyword → list of pattern indices that contain this keyword
	keywordToPatterns map[int][]int
}

var (
	acCache   = map[*operators.Extractor]*acIndex{}
	acCacheMu sync.RWMutex
)

// extractKeywords pulls all literal keyword candidates from a regex pattern.
// For alternations like (key|password|passwd), it returns all alternatives.
func extractKeywords(pattern string) []string {
	clean := strings.Replace(pattern, "(?i)", "", 1)

	// Find alternation groups like (key|password|passwd|...)
	altRe := regexp.MustCompile(`\(([a-zA-Z_|]+)\)`)
	if m := altRe.FindStringSubmatch(clean); len(m) > 1 {
		parts := strings.Split(m[1], "|")
		var result []string
		for _, p := range parts {
			w := wordRe.FindString(p)
			if len(w) >= 2 {
				result = append(result, strings.ToLower(w))
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Fallback: extract the first word
	clean = strings.TrimLeft(clean, `["'\]?^`)
	w := wordRe.FindString(clean)
	if len(w) >= 2 {
		return []string{strings.ToLower(w)}
	}
	return nil
}

func buildACIndex(extractor *operators.Extractor) *acIndex {
	acCacheMu.RLock()
	if idx, ok := acCache[extractor]; ok {
		acCacheMu.RUnlock()
		return idx
	}
	acCacheMu.RUnlock()

	keywords := make([]string, 0, len(extractor.Regex))
	kwToPatterns := make(map[int][]int)
	seen := map[string]int{}

	for i, pattern := range extractor.Regex {
		kws := extractKeywords(pattern)
		if len(kws) == 0 {
			kwToPatterns[-1] = append(kwToPatterns[-1], i)
			continue
		}
		for _, kw := range kws {
			if kwIdx, ok := seen[kw]; ok {
				kwToPatterns[kwIdx] = append(kwToPatterns[kwIdx], i)
			} else {
				kwIdx = len(keywords)
				seen[kw] = kwIdx
				keywords = append(keywords, kw)
				kwToPatterns[kwIdx] = append(kwToPatterns[kwIdx], i)
			}
		}
	}

	if len(keywords) == 0 {
		return nil
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.StandardMatch,
		DFA:                  true,
	})
	ac := builder.Build(keywords)

	idx := &acIndex{
		ac:                ac,
		patterns:          keywords,
		keywordToPatterns: kwToPatterns,
	}

	acCacheMu.Lock()
	acCache[extractor] = idx
	acCacheMu.Unlock()

	return idx
}

// extractRegexWithAC uses Aho-Corasick pre-filtering to avoid running
// all regex patterns on every line. It first scans the corpus with AC
// to find which keywords appear, then only runs the regex patterns
// associated with those keywords.
func (request *Request) extractRegexWithAC(extractor *operators.Extractor, corpus string) map[string]struct{} {
	idx := buildACIndex(extractor)
	if idx == nil {
		return request.extractRegexRE2(extractor, corpus)
	}

	matches := idx.ac.FindAll(corpus)

	if len(matches) == 0 && len(idx.keywordToPatterns[-1]) == 0 {
		return nil
	}

	// Collect which pattern indices need to run
	needRun := make(map[int]bool)

	// Always-run patterns (no extractable keyword)
	for _, pi := range idx.keywordToPatterns[-1] {
		needRun[pi] = true
	}

	// Patterns whose keyword was found
	for _, m := range matches {
		for _, pi := range idx.keywordToPatterns[m.Pattern()] {
			needRun[pi] = true
		}
	}

	if len(needRun) == 0 {
		return nil
	}

	// Only run the matching subset of regex patterns
	regexes := getOrCompileRE2Slice(&extractor.Regex)
	results := make(map[string]struct{})
	groupPlusOne := extractor.RegexGroup + 1

	for pi := range needRun {
		if pi >= len(regexes) || regexes[pi] == nil {
			continue
		}
		found := regexes[pi].FindAllStringSubmatch(corpus, -1)
		for _, match := range found {
			if len(match) < groupPlusOne {
				continue
			}
			results[match[extractor.RegexGroup]] = struct{}{}
		}
	}
	return results
}
