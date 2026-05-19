package file

import (
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

// quickExecute performs a two-phase check: first it tests matchers/extractors
// without allocating a Result, and only falls through to the full Execute path
// when something actually matches. This eliminates the Result{} + 4 map allocs
// for every non-matching line.
func (request *Request) quickExecute(dslMap protocols.InternalEvent) *operators.Result {
	ops := request.CompiledOperators
	if ops == nil {
		return nil
	}

	// Phase 1: quick check extractors without allocating Result
	var hasExtracts bool
	for _, extractor := range ops.Extractors {
		results := request.Extract(dslMap, extractor)
		if len(results) > 0 {
			hasExtracts = true
			break
		}
	}

	// Phase 2: quick check matchers
	var hasMatch bool
	for _, matcher := range ops.Matchers {
		if isMatch, _ := request.Match(dslMap, matcher); isMatch {
			hasMatch = true
			if ops.GetMatchersCondition() == operators.ORCondition {
				break
			}
		} else if ops.GetMatchersCondition() == operators.ANDCondition {
			return nil
		}
	}

	if !hasMatch && !hasExtracts {
		return nil // zero allocation fast path
	}

	// Confirmed match — do full execution to collect results
	result, _ := ops.Execute(dslMap, request.Match, request.Extract)
	return result
}

// matchWordsStatic is a fast path for WordsMatcher that skips common.Evaluate
// when the matcher words contain no dynamic template expressions.
func (request *Request) matchWordsStatic(matcher *operators.Matcher, corpus string) (bool, []string) {
	if matcher.CaseInsensitive {
		corpus = strings.ToLower(corpus)
	}
	var matchedWords []string
	isAND := strings.EqualFold(matcher.Condition, "and")
	for i, word := range matcher.Words {
		if !strings.Contains(corpus, word) {
			if isAND {
				return matcher.ResultWithMatchedSnippet(false, []string{})
			}
			continue
		}
		if !isAND && !matcher.MatchAll {
			return matcher.ResultWithMatchedSnippet(true, []string{word})
		}
		matchedWords = append(matchedWords, word)
		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return matcher.ResultWithMatchedSnippet(true, matchedWords)
		}
	}
	if len(matchedWords) > 0 && matcher.MatchAll {
		return matcher.ResultWithMatchedSnippet(true, matchedWords)
	}
	return matcher.ResultWithMatchedSnippet(false, []string{})
}

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *operators.Matcher) (bool, []string) {
	itemStr, _ := request.getMatchPart(matcher.Part, data)

	switch matcher.GetType() {
	case operators.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), []string{}
	case operators.WordsMatcher:
		if request.staticWordMatchers[matcher] {
			return request.matchWordsStatic(matcher, itemStr)
		}
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, data))
	case operators.RegexMatcher:
		return request.matchRegexRE2(matcher, itemStr)
	case operators.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	case operators.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	}
	return false, []string{}
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *operators.Extractor) map[string]struct{} {
	itemStr, _ := request.getMatchPart(extractor.Part, data)

	switch extractor.GetType() {
	case operators.RegexExtractor:
		if len(extractor.Regex) > 10 {
			return request.extractRegexWithAC(extractor, itemStr)
		}
		return request.extractRegexRE2(extractor, itemStr)
	case operators.KValExtractor:
		return extractor.ExtractKval(data)
	case operators.DSLExtractor:
		return extractor.ExtractDSL(data)
	//case operators.XPathExtractor: // 影响兼容性和文件体积
	//	return extractor.ExtractXPath(itemStr)
	default:
	}
	return nil
}

func (request *Request) getMatchPart(part string, data protocols.InternalEvent) (string, bool) {
	switch part {
	case "body", "all", "data", "":
		part = "raw"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	itemStr := common.ToString(item)

	return itemStr, true
}

// responseToDSLMap converts a file chunk elaboration to a map for use in DSL matching
func (request *Request) responseToDSLMap(raw, inputFilePath, matchedFileName string) protocols.InternalEvent {
	return protocols.InternalEvent{
		"path":    inputFilePath,
		"matched": matchedFileName,
		"raw":     raw,
		"type":    request.Type().String(),
		//"template-id":   request.options.TemplateID,
		//"template-info": request.options.TemplateInfo,
		//"template-path": request.options.TemplatePath,
	}
}

// MakeResultEvent creates a result event from internal wrapped event
// Deprecated: unused in stream mode, must be present for interface compatibility
//func (request *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
//	return protocols.MakeDefaultResultEvent(request, wrapped)
//}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

// MakeResultEventItem
// Deprecated: unused in stream mode, must be present for interface compatibility
func (request *Request) MakeResultEventItem(wrapped *protocols.InternalWrappedEvent) *protocols.ResultEvent {
	data := &protocols.ResultEvent{
		//MatcherStatus: true,
		TemplateID: common.ToString(wrapped.InternalEvent["template-id"]),
		//TemplatePath:     common.ToString(wrapped.InternalEvent["template-path"]),
		//Info:             wrapped.InternalEvent["template-info"].(model.Info),
		Type:             common.ToString(wrapped.InternalEvent["type"]),
		Path:             common.ToString(wrapped.InternalEvent["path"]),
		Matched:          common.ToString(wrapped.InternalEvent["matched"]),
		Host:             common.ToString(wrapped.InternalEvent["host"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		//Response:         common.ToString(wrapped.InternalEvent["raw"]),
		Timestamp: time.Now(),
	}
	return data
}
