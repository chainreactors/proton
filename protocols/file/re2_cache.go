package file

import (
	"strings"
	"sync"

	"github.com/chainreactors/neutron/operators"
	regexp "github.com/wasilibs/go-re2"
)

var (
	re2Cache   = make(map[string]*regexp.Regexp)
	re2CacheMu sync.RWMutex

	re2SliceCache   = make(map[*[]string][]*regexp.Regexp)
	re2SliceCacheMu sync.RWMutex
)

func getOrCompileRE2(pattern string) *regexp.Regexp {
	re2CacheMu.RLock()
	if r, ok := re2Cache[pattern]; ok {
		re2CacheMu.RUnlock()
		return r
	}
	re2CacheMu.RUnlock()

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	re2CacheMu.Lock()
	re2Cache[pattern] = compiled
	re2CacheMu.Unlock()
	return compiled
}

// getOrCompileRE2Slice returns a cached compiled regex slice for the given
// pattern list pointer. This avoids re-creating the slice on every call.
func getOrCompileRE2Slice(patterns *[]string) []*regexp.Regexp {
	re2SliceCacheMu.RLock()
	if cached, ok := re2SliceCache[patterns]; ok {
		re2SliceCacheMu.RUnlock()
		return cached
	}
	re2SliceCacheMu.RUnlock()

	compiled := make([]*regexp.Regexp, 0, len(*patterns))
	for _, p := range *patterns {
		if r := getOrCompileRE2(p); r != nil {
			compiled = append(compiled, r)
		}
	}

	re2SliceCacheMu.Lock()
	re2SliceCache[patterns] = compiled
	re2SliceCacheMu.Unlock()
	return compiled
}

func (request *Request) matchRegexRE2(matcher *operators.Matcher, corpus string) (bool, []string) {
	regexes := getOrCompileRE2Slice(&matcher.Regex)
	if len(regexes) == 0 {
		return false, []string{}
	}

	isAND := strings.EqualFold(matcher.Condition, "and")
	var matchedRegexes []string

	for i, re := range regexes {
		if !re.MatchString(corpus) {
			if isAND {
				return matcher.ResultWithMatchedSnippet(false, []string{})
			}
			continue
		}

		currentMatches := re.FindAllString(corpus, -1)
		if !isAND && !matcher.MatchAll {
			return matcher.ResultWithMatchedSnippet(true, currentMatches)
		}

		matchedRegexes = append(matchedRegexes, currentMatches...)

		if len(regexes)-1 == i && !matcher.MatchAll {
			return matcher.ResultWithMatchedSnippet(true, matchedRegexes)
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return matcher.ResultWithMatchedSnippet(true, matchedRegexes)
	}
	return matcher.ResultWithMatchedSnippet(false, []string{})
}

func (request *Request) extractRegexRE2(extractor *operators.Extractor, corpus string) map[string]struct{} {
	regexes := getOrCompileRE2Slice(&extractor.Regex)
	results := make(map[string]struct{})

	groupPlusOne := extractor.RegexGroup + 1
	for _, re := range regexes {
		matches := re.FindAllStringSubmatch(corpus, -1)
		for _, match := range matches {
			if len(match) < groupPlusOne {
				continue
			}
			results[match[extractor.RegexGroup]] = struct{}{}
		}
	}
	return results
}
