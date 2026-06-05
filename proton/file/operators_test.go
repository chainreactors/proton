package file

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
)

func TestResponseToDSLMap(t *testing.T) {
	request := &Request{
		ID:          "testing-file",
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all"},
		DenyList:    []string{".go"},
	}
	err := request.Compile(newTestOptions())
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n"
	event := request.responseToDSLMap(resp, "/tmp/input", "matched.txt")
	require.Len(t, event, 4, "could not get correct number of items in dsl map")
	require.Equal(t, resp, event["raw"], "could not get correct resp")
	require.Equal(t, "/tmp/input", event["path"])
	require.Equal(t, "matched.txt", event["matched"])
	require.Equal(t, "file", event["type"])
}

func TestFileOperatorMatch(t *testing.T) {
	request := &Request{
		ID:          "testing-file",
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all"},
		DenyList:    []string{".go"},
	}
	err := request.Compile(newTestOptions())
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n1.1.1.1\r\n"
	event := request.responseToDSLMap(resp, "/tmp/input", "matched.txt")

	t.Run("valid", func(t *testing.T) {
		matcher := &operators.Matcher{
			Part:  "raw",
			Type:  "word",
			Words: []string{"1.1.1.1"},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid response")
		require.Equal(t, matcher.Words, matched)
	})

	t.Run("negative", func(t *testing.T) {
		matcher := &operators.Matcher{
			Part:     "raw",
			Type:     "word",
			Negative: true,
			Words:    []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile negative matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid negative response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("invalid", func(t *testing.T) {
		matcher := &operators.Matcher{
			Part:  "raw",
			Type:  "word",
			Words: []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.False(t, isMatched, "could match invalid response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("caseInsensitive", func(t *testing.T) {
		resp := "TEST-DATA\r\n1.1.1.1\r\n"
		event := request.responseToDSLMap(resp, "/tmp/input", "matched.txt")

		matcher := &operators.Matcher{
			Part:            "raw",
			Type:            "word",
			Words:           []string{"TeSt-DaTA"},
			CaseInsensitive: true,
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid response")
		require.Equal(t, []string{"test-data"}, matched)
	})
}

func TestFileOperatorExtract(t *testing.T) {
	request := &Request{
		ID:          "testing-file",
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all"},
		DenyList:    []string{".go"},
	}
	err := request.Compile(newTestOptions())
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n1.1.1.1\r\n"
	event := request.responseToDSLMap(resp, "/tmp/input", "matched.txt")

	t.Run("extract", func(t *testing.T) {
		extractor := &operators.Extractor{
			Part:  "raw",
			Type:  "regex",
			Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extract valid response")
		require.Equal(t, map[string]struct{}{"1.1.1.1": {}}, data, "could not extract correct data")
	})

	t.Run("kval", func(t *testing.T) {
		extractor := &operators.Extractor{
			Type: "kval",
			KVal: []string{"raw"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile kval extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extract kval valid response")
		require.Equal(t, map[string]struct{}{resp: {}}, data, "could not extract correct kval data")
	})
}

func TestFileMakeResultWithOrMatcher(t *testing.T) {
	expectedValue := []string{"1.1.1.1"}
	namedMatcherName := "test"

	finalEvent := testFileMakeResult(t, "or")
	require.Equal(t, namedMatcherName, finalEvent.Results[0].MatcherName)
	require.Equal(t, expectedValue, finalEvent.OperatorsResult.Matches[namedMatcherName], "could not get matched value")
}

func TestFileMakeResultWithAndMatcher(t *testing.T) {
	finalEvent := testFileMakeResult(t, "and")
	require.NotEmpty(t, finalEvent.OperatorsResult.Matches, "AND condition should populate matches")
}

func testFileMakeResult(t *testing.T, matcherCondition string) *protocols.InternalWrappedEvent {
	expectedValue := []string{"1.1.1.1"}
	namedMatcherName := "test"

	request := &Request{
		ID:          "testing-file",
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all"},
		DenyList:    []string{".go"},
		Operators: operators.Operators{
			MatchersCondition: matcherCondition,
			Matchers: []*operators.Matcher{
				{
					Part:  "raw",
					Type:  "word",
					Words: expectedValue,
				},
				{
					Name:  namedMatcherName,
					Part:  "raw",
					Type:  "word",
					Words: expectedValue,
				},
			},
			Extractors: []*operators.Extractor{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
	}
	err := request.Compile(newTestOptions())
	require.Nil(t, err, "could not compile file request")

	matchedFileName := "test.txt"
	fileContent := "test-data\r\n1.1.1.1\r\n"

	event := request.responseToDSLMap(fileContent, "/tmp", matchedFileName)
	require.Equal(t, fileContent, event["raw"], "could not get correct resp")

	finalEvent := &protocols.InternalWrappedEvent{InternalEvent: event}
	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(event, request.Match, request.Extract)
		if ok && result != nil {
			finalEvent.OperatorsResult = result
			finalEvent.Results = request.MakeResultEvent(finalEvent)
		}
	}
	require.NotNil(t, finalEvent.OperatorsResult, "operator result should not be nil")
	require.True(t, len(finalEvent.Results) > 0, "should have at least one result")

	resultEvent := finalEvent.Results[0]
	require.Equal(t, "1.1.1.1", resultEvent.ExtractedResults[0], "could not get correct extracted results")
	require.Equal(t, matchedFileName, resultEvent.Matched, "could not get matched value")

	return finalEvent
}
