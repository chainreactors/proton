//go:build go1.18
// +build go1.18

package file

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/operators"
	"github.com/charlievieth/fastwalk"
	"github.com/mholt/archives"
	regexp "github.com/wasilibs/go-re2"
)

// --- directory walk (fastwalk) ---

func parallelWalk(root string, fn func(path string, d fs.DirEntry, err error) error) error {
	return fastwalk.Walk(nil, root, fn)
}

// --- regexp cache (wasilibs/go-re2) ---

var (
	re2Cache   = make(map[string]*regexp.Regexp)
	re2CacheMu sync.RWMutex

	re2SliceCache   = make(map[*[]string][]*regexp.Regexp)
	re2SliceCacheMu sync.RWMutex
)

func getOrCompileRE2(pattern string) compiledRegexp {
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

func getOrCompileRE2Slice(patterns *[]string) []*regexp.Regexp {
	re2SliceCacheMu.RLock()
	if cached, ok := re2SliceCache[patterns]; ok {
		re2SliceCacheMu.RUnlock()
		return cached
	}
	re2SliceCacheMu.RUnlock()

	compiled := make([]*regexp.Regexp, 0, len(*patterns))
	for _, p := range *patterns {
		r, err := regexp.Compile(p)
		if err == nil {
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

// --- archive fallback (mholt/archives) ---

func (s *Scanner) scanArchiveFallback(archivePath string, group *scanGroup) []Finding {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	format, _, err := archives.Identify(context.Background(), archivePath, f)
	if err != nil || format == nil {
		return nil
	}
	f.Seek(0, 0)
	ex, ok := format.(archives.Extractor)
	if !ok {
		return nil
	}
	var findings []Finding
	entries := 0
	ex.Extract(context.Background(), f, func(ctx context.Context, fi archives.FileInfo) error {
		if fi.IsDir() || fi.Size() == 0 || fi.Size() > maxArchiveEntrySize {
			return nil
		}
		entryExt := filepath.Ext(fi.Name())
		if _, deny := alwaysDenyExts[entryExt]; deny {
			return nil
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("too many entries")
		}
		rc, err := fi.Open()
		if err != nil {
			return nil
		}
		defer rc.Close()
		data, err := io.ReadAll(io.LimitReader(rc, maxArchiveEntrySize))
		if err != nil || len(data) == 0 {
			return nil
		}
		entryPath := fmt.Sprintf("%s:%s", archivePath, fi.Name())
		findings = append(findings, s.scanData(data, entryPath, group)...)
		return nil
	})
	return findings
}
