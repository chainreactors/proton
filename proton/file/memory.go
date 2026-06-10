package file

import (
	"github.com/chainreactors/neutron/operators"
)

var (
	MemWindowSize  = 32 * 1024 // 32KB: best process-scan latency per benchmark
	MemOverlapSize = 512
)

func (s *Scanner) scanMemBlock(data []byte, baseAddr uint64, label string, group *scanGroup) []Finding {
	results := s.initFileResults(group.Templates)

	srcBuf := make([]int, 0, len(group.patternSources))
	srcSeen := make([]bool, len(group.patternSources))

	step := MemWindowSize - MemOverlapSize
	if step <= 0 {
		step = MemWindowSize
	}

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
