package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	mmap "github.com/edsrzf/mmap-go"
	"github.com/chainreactors/utils/ahocorasick"
)

type patternSource struct {
	Pattern     string
	TemplateIdx int
	IsExtractor bool
	OperatorIdx int
	RegexGroup  int
}

type ruleRef struct {
	ID       string
	Severity string
	Name     string
	Request  *Request
}

type ScanGroup = scanGroup

type scanGroup struct {
	AllExtensions bool
	Extensions    map[string]struct{}
	UseTextOnly   bool
	DenyList      map[string]struct{}

	Templates      []*ruleRef
	patternSources []patternSource
	prefilter      *linePrefilter
	index          *patternIndex
}

type patternIndex struct {
	ac               *ahocorasick.Automaton
	literals         []string
	literalToSources map[int][]int
	fallbackSources  []int
}

type matchHit struct {
	Value  string
	Line   int
	Offset int
}

type fileResult struct {
	matcherHits   map[int][]matchHit
	extractorHits map[int][]matchHit
}

type MatchEvent struct {
	Value  string `json:"value"`
	Line   int    `json:"line"`
	Offset int    `json:"offset,omitempty"`
}

type Finding struct {
	TemplateID   string
	TemplateName string
	Severity     string
	FilePath     string
	Matches      map[string][]MatchEvent
	Extracts     []MatchEvent
	Result       *operators.Result
}

type ScanStats struct {
	Files    int64
	Regions  int64
	Bytes    int64
	Findings int64
	Rules    int
}

func (s ScanStats) HumanBytes() string {
	return common.HumanSize(float64(s.Bytes))
}

type Scanner struct {
	Groups         []*scanGroup
	Options        *protocols.ExecuterOptions
	Stats          ScanStats
	fileResultPool sync.Pool
}

type Rule struct {
	ID       string
	Name     string
	Severity string
	Requests []*Request
}

func extensionKey(req *Request) string {
	if req.allExtensions {
		return "all"
	}
	exts := make([]string, 0, len(req.extensions))
	for ext := range req.extensions {
		exts = append(exts, ext)
	}
	sort.Strings(exts)
	return strings.Join(exts, ",")
}

func NewScanner(inputs []Rule, opts *protocols.ExecuterOptions) *Scanner {
	groupMap := make(map[string]*scanGroup)

	for inputIdx := range inputs {
		input := &inputs[inputIdx]
		for _, req := range input.Requests {
			key := extensionKey(req)
			group, ok := groupMap[key]
			if !ok {
				group = &scanGroup{
					AllExtensions: req.allExtensions,
					Extensions:    make(map[string]struct{}),
					DenyList:      make(map[string]struct{}),
				}
				groupMap[key] = group
			}
			for ext := range req.extensions {
				group.Extensions[ext] = struct{}{}
			}
			for deny := range req.denyList {
				group.DenyList[deny] = struct{}{}
			}
			if req.useTextOnly {
				group.UseTextOnly = true
			}
			tmplRef := &ruleRef{ID: input.ID, Severity: input.Severity, Name: input.Name, Request: req}
			tmplIdx := len(group.Templates)
			group.Templates = append(group.Templates, tmplRef)

			if req.CompiledOperators != nil {
				for mIdx, matcher := range req.CompiledOperators.Matchers {
					if matcher.GetType() == operators.RegexMatcher {
						for _, pattern := range matcher.Regex {
							group.patternSources = append(group.patternSources, patternSource{
								Pattern: pattern, TemplateIdx: tmplIdx, OperatorIdx: mIdx,
							})
						}
					}
				}
				for eIdx, extractor := range req.CompiledOperators.Extractors {
					if extractor.GetType() == operators.RegexExtractor {
						for _, pattern := range extractor.Regex {
							group.patternSources = append(group.patternSources, patternSource{
								Pattern: pattern, TemplateIdx: tmplIdx, IsExtractor: true,
								OperatorIdx: eIdx, RegexGroup: extractor.RegexGroup,
							})
						}
					}
				}
			}
		}
	}

	groups := make([]*scanGroup, 0, len(groupMap))
	for _, group := range groupMap {
		group.prefilter = buildGroupPrefilter(group.Templates)
		group.index = buildPatternIndex(group.patternSources)
		groups = append(groups, group)
	}
	return &Scanner{
		Groups:  groups,
		Options: opts,
		Stats:   ScanStats{Rules: len(inputs)},
	}
}

func buildPatternIndex(sources []patternSource) *patternIndex {
	idx := &patternIndex{literalToSources: make(map[int][]int)}
	var allLiterals []string
	litLookup := make(map[string]int)

	for srcIdx, src := range sources {
		lits := extractLiterals(src.Pattern)
		if len(lits) == 0 {
			idx.fallbackSources = append(idx.fallbackSources, srcIdx)
			continue
		}
		for _, lit := range lits {
			lower := strings.ToLower(lit)
			litIdx, ok := litLookup[lower]
			if !ok {
				litIdx = len(allLiterals)
				litLookup[lower] = litIdx
				allLiterals = append(allLiterals, lower)
			}
			idx.literalToSources[litIdx] = append(idx.literalToSources[litIdx], srcIdx)
		}
	}
	idx.literals = allLiterals
	if len(allLiterals) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(allLiterals).
			SetMatchKind(ahocorasick.LeftmostLongest).
			Build()
		if err == nil {
			idx.ac = ac
		}
	}
	return idx
}

func buildGroupPrefilter(templates []*ruleRef) *linePrefilter {
	var allLiterals []string
	var hasCaseInsensitive bool

	for _, tmplRef := range templates {
		req := tmplRef.Request
		if req.CompiledOperators == nil {
			continue
		}
		for _, ext := range req.CompiledOperators.Extractors {
			if ext.GetType() != operators.RegexExtractor {
				continue
			}
			for _, pattern := range ext.Regex {
				lits := extractLiterals(pattern)
				if len(lits) == 0 {
					return &linePrefilter{disabled: true}
				}
				allLiterals = append(allLiterals, lits...)
				if strings.HasPrefix(pattern, "(?i)") {
					hasCaseInsensitive = true
				}
			}
		}
		for _, m := range req.CompiledOperators.Matchers {
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
						return &linePrefilter{disabled: true}
					}
				}
				if m.CaseInsensitive {
					hasCaseInsensitive = true
				}
			case operators.DSLMatcher:
				return &linePrefilter{disabled: true}
			}
		}
	}
	if len(allLiterals) == 0 {
		return &linePrefilter{disabled: true}
	}
	seen := make(map[string]struct{}, len(allLiterals))
	deduped := make([]string, 0, len(allLiterals))
	for _, lit := range allLiterals {
		if _, ok := seen[lit]; !ok {
			seen[lit] = struct{}{}
			deduped = append(deduped, lit)
		}
	}
	allLiterals = deduped

	// When there are many literals, bytes.Contains × N becomes slower than
	// a single AC pass. In that case, disable the prefilter entirely and let
	// patternIndex (which already has its own AC) handle filtering.
	// Benchmark shows the crossover at ~50 patterns; we use a conservative
	// threshold since the prefilter also avoids string(line) conversion.
	const maxPrefilterLiterals = 30

	if len(allLiterals) > maxPrefilterLiterals {
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
	return f
}

// relevantSources returns indices into patternSources that may match the line.
// Uses a reusable bitset to avoid per-line allocation.
func (idx *patternIndex) relevantSources(line string, buf *[]int, seen []bool) []int {
	return idx.relevantSourcesBytes([]byte(strings.ToLower(line)), buf, seen)
}

func (idx *patternIndex) relevantSourcesBytes(lower []byte, buf *[]int, seen []bool) []int {
	if idx == nil || idx.ac == nil {
		return idx.fallbackSources
	}
	hits := idx.ac.FindAll(lower, -1)
	if len(hits) == 0 && len(idx.fallbackSources) == 0 {
		return nil
	}
	result := (*buf)[:0]
	for _, hit := range hits {
		for _, srcIdx := range idx.literalToSources[hit.PatternID] {
			if !seen[srcIdx] {
				seen[srcIdx] = true
				result = append(result, srcIdx)
			}
		}
	}
	for _, srcIdx := range idx.fallbackSources {
		if !seen[srcIdx] {
			seen[srcIdx] = true
			result = append(result, srcIdx)
		}
	}
	for _, srcIdx := range result {
		seen[srcIdx] = false
	}
	*buf = result
	return result
}

func (s *Scanner) Scan(target string, callback func(Finding)) error {
	numWorkers := runtime.NumCPU()
	type fileJob struct {
		path  string
		group *scanGroup
	}
	jobCh := make(chan fileJob, numWorkers*256)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				findings := s.processFile(job.path, job.group)
				if len(findings) > 0 {
					atomic.AddInt64(&s.Stats.Findings, int64(len(findings)))
					cbMu.Lock()
					for _, f := range findings {
						callback(f)
					}
					cbMu.Unlock()
				}
			}
		}()
	}

	// Stream dispatch: walk and process in parallel.
	walkErr := parallelWalk(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, skip := defaultSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := filepath.Ext(path)
		if _, deny := alwaysDenyExts[ext]; deny {
			return nil
		}
		for _, group := range s.Groups {
			if !group.matchesFile(path, ext) {
				continue
			}
			jobCh <- fileJob{path: path, group: group}
		}
		return nil
	})
	close(jobCh)
	wg.Wait()
	return walkErr
}

func (g *scanGroup) matchesFile(path, ext string) bool {
	if _, ok := archiveDenyExts[ext]; ok {
		return true
	}
	if !g.AllExtensions {
		if _, ok := g.Extensions[ext]; !ok {
			return false
		}
	}
	if _, ok := g.DenyList[ext]; ok {
		return false
	}
	if g.UseTextOnly && ext != "" {
		if _, ok := textExtensions[strings.ToLower(ext)]; !ok {
			return false
		}
	}
	return true
}

const unifiedMmapMinSize = 32 * 1024

func (s *Scanner) processFile(path string, group *scanGroup) []Finding {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	size := info.Size()
	if size == 0 || size > defaultMaxReadSize {
		return nil
	}

	atomic.AddInt64(&s.Stats.Files, 1)
	atomic.AddInt64(&s.Stats.Bytes, size)

	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := archiveDenyExts[ext]; ok {
		return s.processArchive(path, group)
	}

	var data []byte
	var mapped mmap.MMap
	if size >= unifiedMmapMinSize {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		mapped, err = mmap.Map(file, mmap.RDONLY, 0)
		file.Close()
		if err != nil {
			data, _ = os.ReadFile(path)
		} else {
			data = mapped
		}
	} else {
		data, _ = os.ReadFile(path)
	}
	if data == nil {
		return nil
	}
	if mapped != nil {
		defer mapped.Unmap()
	}

	if group.UseTextOnly {
		if ext == "" || func() bool { _, ok := textExtensions[ext]; return !ok }() {
			sample := data
			if len(sample) > 1024 {
				sample = sample[:1024]
			}
			if !isTextContent(sample) {
				return nil
			}
		}
	}

	return s.scanData(data, path, group)
}

// ScanData runs the line-scanning pipeline on in-memory content and returns findings.
// This is the primary entry point for callers that already have the data in memory
// (e.g. spray processing HTTP response bodies).
func (s *Scanner) ScanData(data []byte, filePath string, group *scanGroup) []Finding {
	return s.scanData(data, filePath, group)
}

// scanData runs the line-scanning pipeline on raw content and returns findings.
func (s *Scanner) scanData(data []byte, filePath string, group *scanGroup) []Finding {
	results := s.getFileResults(len(group.Templates))

	srcBuf := make([]int, 0, len(group.patternSources))
	srcSeen := make([]bool, len(group.patternSources))

	lineNum := 0
	byteOffset := 0
	remaining := data
	for len(remaining) > 0 {
		idx := bytes.IndexByte(remaining, '\n')
		var line []byte
		if idx >= 0 {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		} else {
			line = remaining
			remaining = nil
		}
		lineNum++
		lineOffset := byteOffset
		byteOffset += len(line) + 1
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if group.prefilter != nil && !group.prefilter.mayMatch(line) {
			continue
		}

		lineStr := string(line)

		relevant := group.index.relevantSources(lineStr, &srcBuf, srcSeen)
		for _, srcIdx := range relevant {
			src := &group.patternSources[srcIdx]
			re := getOrCompileRE2(src.Pattern)
			if re == nil {
				continue
			}
			if src.IsExtractor {
				matches := re.FindAllStringSubmatch(lineStr, -1)
				if len(matches) == 0 {
					continue
				}
				groupPlusOne := src.RegexGroup + 1
				res := &results[src.TemplateIdx]
				for _, m := range matches {
					if len(m) >= groupPlusOne {
						res.extractorHits[src.OperatorIdx] = append(
							res.extractorHits[src.OperatorIdx],
							matchHit{Value: m[src.RegexGroup], Line: lineNum, Offset: lineOffset})
					}
				}
			} else {
				if re.MatchString(lineStr) {
					matched := re.FindAllString(lineStr, -1)
					res := &results[src.TemplateIdx]
					for _, val := range matched {
						res.matcherHits[src.OperatorIdx] = append(
							res.matcherHits[src.OperatorIdx],
							matchHit{Value: val, Line: lineNum, Offset: lineOffset})
					}
				}
			}
		}

		for tmplIdx, tmplRef := range group.Templates {
			req := tmplRef.Request
			if req.CompiledOperators == nil {
				continue
			}
			for matcherIdx, matcher := range req.CompiledOperators.Matchers {
				switch matcher.GetType() {
				case operators.WordsMatcher:
					if matched, words := req.matchWordsOnCorpus(matcher, lineStr); matched {
						for _, w := range words {
							results[tmplIdx].matcherHits[matcherIdx] = append(
								results[tmplIdx].matcherHits[matcherIdx],
								matchHit{Value: w, Line: lineNum, Offset: lineOffset})
						}
					}
				case operators.BinaryMatcher:
					if matched, bins := matcher.MatchBinary(lineStr); matched {
						for _, b := range bins {
							results[tmplIdx].matcherHits[matcherIdx] = append(
								results[tmplIdx].matcherHits[matcherIdx],
								matchHit{Value: b, Line: lineNum, Offset: lineOffset})
						}
					}
				}
			}
		}
	}

	var findings []Finding
	for tmplIdx, tmplRef := range group.Templates {
		res := &results[tmplIdx]
		if finding := buildFinding(tmplRef, res, filePath); finding != nil {
			findings = append(findings, *finding)
		}
	}
	s.putFileResults(results)
	return findings
}

const maxArchiveEntries = 10000
const maxArchiveEntrySize = 100 * 1024 * 1024

// processArchive scans files inside an archive.
// Uses stdlib for tar/gz/zip (fastest), falls back to mholt/archiver v3 for other formats.
func (s *Scanner) processArchive(archivePath string, group *scanGroup) []Finding {
	ext := strings.ToLower(filepath.Ext(archivePath))

	switch ext {
	case ".tar":
		return s.scanTar(archivePath, nil, group)
	case ".gz", ".tgz":
		return s.scanTarGz(archivePath, group)
	case ".zip", ".jar", ".apk":
		return s.scanZip(archivePath, group)
	default:
		return s.scanArchiveFallback(archivePath, group)
	}
}

func (s *Scanner) scanTar(archivePath string, r io.Reader, group *scanGroup) []Finding {
	if r == nil {
		f, err := os.Open(archivePath)
		if err != nil {
			return nil
		}
		defer f.Close()
		r = f
	}
	tr := tar.NewReader(r)
	var findings []Finding
	entries := 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 || hdr.Size > maxArchiveEntrySize {
			continue
		}
		entryExt := filepath.Ext(hdr.Name)
		if _, deny := alwaysDenyExts[entryExt]; deny {
			continue
		}
		entries++
		if entries > maxArchiveEntries {
			break
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxArchiveEntrySize))
		if err != nil || len(data) == 0 {
			continue
		}
		entryPath := fmt.Sprintf("%s:%s", archivePath, hdr.Name)
		findings = append(findings, s.scanData(data, entryPath, group)...)
	}
	return findings
}

func (s *Scanner) scanTarGz(archivePath string, group *scanGroup) []Finding {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gr.Close()
	return s.scanTar(archivePath, gr, group)
}

func (s *Scanner) scanZip(archivePath string, group *scanGroup) []Finding {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil
	}
	defer r.Close()
	var findings []Finding
	entries := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 == 0 || int64(f.UncompressedSize64) > maxArchiveEntrySize {
			continue
		}
		entryExt := filepath.Ext(f.Name)
		if _, deny := alwaysDenyExts[entryExt]; deny {
			continue
		}
		entries++
		if entries > maxArchiveEntries {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxArchiveEntrySize))
		rc.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		entryPath := fmt.Sprintf("%s:%s", archivePath, f.Name)
		findings = append(findings, s.scanData(data, entryPath, group)...)
	}
	return findings
}


func (s *Scanner) getFileResults(n int) []fileResult {
	if v := s.fileResultPool.Get(); v != nil {
		results := v.([]fileResult)
		if len(results) >= n {
			return results[:n]
		}
	}
	results := make([]fileResult, n)
	for i := range results {
		results[i].matcherHits = make(map[int][]matchHit)
		results[i].extractorHits = make(map[int][]matchHit)
	}
	return results
}

func (s *Scanner) putFileResults(results []fileResult) {
	for i := range results {
		for k := range results[i].matcherHits {
			results[i].matcherHits[k] = results[i].matcherHits[k][:0]
			delete(results[i].matcherHits, k)
		}
		for k := range results[i].extractorHits {
			results[i].extractorHits[k] = results[i].extractorHits[k][:0]
			delete(results[i].extractorHits, k)
		}
	}
	s.fileResultPool.Put(results)
}

func (request *Request) matchWordsOnCorpus(matcher *operators.Matcher, corpus string) (bool, []string) {
	if request.staticWordMatchers[matcher] {
		return request.matchWordsStatic(matcher, corpus)
	}
	data := map[string]interface{}{"raw": corpus}
	return matcher.ResultWithMatchedSnippet(matcher.MatchWords(corpus, data))
}

func buildFinding(tmplRef *ruleRef, res *fileResult, filePath string) *Finding {
	req := tmplRef.Request
	ops := req.CompiledOperators
	if ops == nil {
		return nil
	}
	matcherCondition := ops.GetMatchersCondition()
	matched := false
	findingMatches := make(map[string][]MatchEvent)
	resultMatches := make(map[string][]string)

	for idx, matcher := range ops.Matchers {
		hits := res.matcherHits[idx]
		hasMatch := len(hits) > 0
		if matcher.Negative {
			hasMatch = !hasMatch
		}
		if hasMatch {
			name := matcher.Name
			if name == "" {
				name = fmt.Sprintf("matcher-%d", idx)
			}
			for _, h := range hits {
				findingMatches[name] = append(findingMatches[name], MatchEvent{Value: h.Value, Line: h.Line, Offset: h.Offset})
				resultMatches[name] = append(resultMatches[name], h.Value)
			}
			matched = true
			if matcherCondition == operators.ORCondition {
				break
			}
		} else if matcherCondition == operators.ANDCondition {
			return nil
		}
	}

	var findingExtracts []MatchEvent
	resultExtracts := make(map[string][]string)
	var outputExtracts []string
	seen := make(map[string]struct{})
	for idx, ext := range ops.Extractors {
		hits := res.extractorHits[idx]
		if len(hits) == 0 {
			continue
		}
		var extractList []string
		for _, h := range hits {
			extractList = append(extractList, h.Value)
			findingExtracts = append(findingExtracts, MatchEvent{Value: h.Value, Line: h.Line, Offset: h.Offset})
		}
		if ext.Name != "" && !ext.Internal {
			resultExtracts[ext.Name] = extractList
		}
		if !ext.Internal {
			for _, e := range extractList {
				if _, ok := seen[e]; !ok {
					outputExtracts = append(outputExtracts, e)
					seen[e] = struct{}{}
				}
			}
		}
	}

	if !matched && len(outputExtracts) == 0 {
		return nil
	}
	if len(ops.Matchers) > 0 && !matched {
		return nil
	}
	return &Finding{
		TemplateID: tmplRef.ID, TemplateName: tmplRef.Name, Severity: tmplRef.Severity,
		FilePath: filePath,
		Matches:  findingMatches,
		Extracts: findingExtracts,
		Result: &operators.Result{
			Matched: matched, Extracted: len(outputExtracts) > 0,
			Matches: resultMatches, Extracts: resultExtracts, OutputExtracts: outputExtracts,
		},
	}
}


