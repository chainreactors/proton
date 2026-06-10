package file

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/neutron/operators"
)

type MemoryRegion struct {
	BaseAddr   uint64
	Size       uint64
	Perms      string
	MappedFile string
}

type MemoryReader interface {
	Regions() ([]MemoryRegion, error)
	ReadAt(buf []byte, addr uint64) (int, error)
	Close() error
}

type MemoryScanOptions struct {
	ScanAll bool
}

var (
	MemWindowSize  = 32 * 1024 // 32KB: best process-scan latency per benchmark
	MemOverlapSize = 512
)

const (
	maxRegionReadSize  = 64 << 20 // 64MB
	maxRegionChunkSize = 4 << 20  // 4MB per read chunk
)

func shouldScanRegion(r MemoryRegion, opts MemoryScanOptions) bool {
	if !strings.Contains(r.Perms, "r") {
		return false
	}
	if opts.ScanAll {
		return true
	}
	if strings.Contains(r.Perms, "w") {
		return true
	}
	if r.MappedFile == "" || r.MappedFile == "[heap]" || r.MappedFile == "[stack]" ||
		strings.HasPrefix(r.MappedFile, "[") {
		return true
	}
	return false
}

func (s *Scanner) ScanProcess(pid int, opts MemoryScanOptions, callback func(Finding)) error {
	reader, err := newMemoryReader(pid)
	if err != nil {
		return fmt.Errorf("cannot attach to pid %d: %w", pid, err)
	}
	defer reader.Close()

	regions, err := reader.Regions()
	if err != nil {
		return fmt.Errorf("cannot enumerate memory regions for pid %d: %w", pid, err)
	}

	var scanRegions []MemoryRegion
	for _, r := range regions {
		if shouldScanRegion(r, opts) {
			scanRegions = append(scanRegions, r)
		}
	}
	if len(scanRegions) == 0 {
		return nil
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > len(scanRegions) {
		numWorkers = len(scanRegions)
	}

	type memJob struct {
		region MemoryRegion
		group  *scanGroup
	}
	jobCh := make(chan memJob, numWorkers*16)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	label := fmt.Sprintf("pid:%d", pid)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				s.scanRegion(reader, job.region, label, job.group, &cbMu, callback)
			}
		}()
	}

	for _, region := range scanRegions {
		atomic.AddInt64(&s.Stats.Regions, 1)
		for _, group := range s.Groups {
			jobCh <- memJob{region: region, group: group}
		}
	}
	close(jobCh)
	wg.Wait()
	return nil
}

func (s *Scanner) scanRegion(reader MemoryReader, region MemoryRegion, label string, group *scanGroup, cbMu *sync.Mutex, callback func(Finding)) {
	regionSize := region.Size
	if regionSize > maxRegionReadSize {
		regionSize = maxRegionReadSize
	}

	chunkSize := uint64(maxRegionChunkSize)
	if chunkSize > regionSize {
		chunkSize = regionSize
	}

	buf := make([]byte, chunkSize+uint64(MemOverlapSize))

	for offset := uint64(0); offset < regionSize; {
		readSize := chunkSize
		if offset+readSize > regionSize {
			readSize = regionSize - offset
		}
		// include overlap from previous chunk's tail for cross-boundary matches
		readStart := region.BaseAddr + offset
		actualReadSize := readSize
		if offset > 0 && offset >= uint64(MemOverlapSize) {
			readStart = region.BaseAddr + offset - uint64(MemOverlapSize)
			actualReadSize = readSize + uint64(MemOverlapSize)
		}
		if actualReadSize > uint64(len(buf)) {
			actualReadSize = uint64(len(buf))
		}

		n, err := reader.ReadAt(buf[:actualReadSize], readStart)
		if err != nil || n == 0 {
			offset += readSize
			continue
		}

		data := buf[:n]
		atomic.AddInt64(&s.Stats.Bytes, int64(n))

		findings := s.scanMemBlock(data, readStart, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&s.Stats.Findings, int64(len(findings)))
			cbMu.Lock()
			for _, f := range findings {
				callback(f)
			}
			cbMu.Unlock()
		}

		offset += readSize
	}
}

func (s *Scanner) scanMemBlock(data []byte, baseAddr uint64, label string, group *scanGroup) []Finding {
	results := s.getFileResults(len(group.Templates))

	srcBuf := make([]int, 0, len(group.patternSources))
	srcSeen := make([]bool, len(group.patternSources))

	step := MemWindowSize - MemOverlapSize
	if step <= 0 {
		step = MemWindowSize
	}

	// reusable buffer for ASCII-lowercased window (avoids alloc per window)
	lowerBuf := make([]byte, MemWindowSize)

	hasWordOrBinary := false
	for _, tmplRef := range group.Templates {
		if tmplRef.Request.CompiledOperators == nil {
			continue
		}
		for _, m := range tmplRef.Request.CompiledOperators.Matchers {
			t := m.GetType()
			if t == operators.WordsMatcher || t == operators.BinaryMatcher {
				hasWordOrBinary = true
				break
			}
		}
		if hasWordOrBinary {
			break
		}
	}

	for offset := 0; offset < len(data); {
		end := offset + MemWindowSize
		if end > len(data) {
			end = len(data)
		}
		window := data[offset:end]
		virtAddr := baseAddr + uint64(offset)

		ownedEnd := offset + step
		if end == len(data) {
			ownedEnd = end
		}

		if group.prefilter != nil && !group.prefilter.mayMatch(window) {
			offset += step
			continue
		}

		// AC index: lowercase in-place into reusable buffer
		lower := lowerBuf[:len(window)]
		asciiLowerInto(lower, window)

		relevant := group.index.relevantSourcesBytes(lower, &srcBuf, srcSeen)
		for _, srcIdx := range relevant {
			src := &group.patternSources[srcIdx]
			re := getOrCompileRE2(src.Pattern)
			if re == nil {
				continue
			}
			if src.IsExtractor {
				subs := re.FindAllSubmatch(window, -1)
				locs := re.FindAllIndex(window, -1)
				groupIdx := src.RegexGroup
				for i, m := range subs {
					if len(m) <= groupIdx {
						continue
					}
					matchStart := 0
					if i < len(locs) {
						matchStart = locs[i][0]
					}
					if offset+matchStart >= ownedEnd && end != len(data) {
						continue
					}
					matchAddr := virtAddr + uint64(matchStart)
					res := &results[src.TemplateIdx]
					res.extractorHits[src.OperatorIdx] = append(
						res.extractorHits[src.OperatorIdx],
						matchHit{Value: string(m[groupIdx]), Line: 0, Offset: int(matchAddr)})
				}
			} else {
				locs := re.FindAllIndex(window, -1)
				for _, loc := range locs {
					if offset+loc[0] >= ownedEnd && end != len(data) {
						continue
					}
					matchAddr := virtAddr + uint64(loc[0])
					res := &results[src.TemplateIdx]
					res.matcherHits[src.OperatorIdx] = append(
						res.matcherHits[src.OperatorIdx],
						matchHit{Value: string(window[loc[0]:loc[1]]), Line: 0, Offset: int(matchAddr)})
				}
			}
		}

		// word/binary matchers need string; only convert when necessary
		if hasWordOrBinary {
			windowStr := string(window)
			for tmplIdx, tmplRef := range group.Templates {
				req := tmplRef.Request
				if req.CompiledOperators == nil {
					continue
				}
				for matcherIdx, matcher := range req.CompiledOperators.Matchers {
					switch matcher.GetType() {
					case operators.WordsMatcher:
						if matched, words := req.matchWordsOnCorpus(matcher, windowStr); matched {
							for _, w := range words {
								results[tmplIdx].matcherHits[matcherIdx] = append(
									results[tmplIdx].matcherHits[matcherIdx],
									matchHit{Value: w, Line: 0, Offset: int(virtAddr)})
							}
						}
					case operators.BinaryMatcher:
						if matched, bins := matcher.MatchBinary(windowStr); matched {
							for _, b := range bins {
								results[tmplIdx].matcherHits[matcherIdx] = append(
									results[tmplIdx].matcherHits[matcherIdx],
									matchHit{Value: b, Line: 0, Offset: int(virtAddr)})
							}
						}
					}
				}
			}
		}

		if end == len(data) {
			break
		}
		offset += step
	}

	var findings []Finding
	for tmplIdx, tmplRef := range group.Templates {
		res := &results[tmplIdx]
		if finding := buildFinding(tmplRef, res, label); finding != nil {
			findings = append(findings, *finding)
		}
	}
	s.putFileResults(results)
	return findings
}

func asciiLowerInto(dst, src []byte) {
	for i, b := range src {
		if b >= 'A' && b <= 'Z' {
			dst[i] = b + ('a' - 'A')
		} else {
			dst[i] = b
		}
	}
}
