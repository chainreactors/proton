package file

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	mmap "github.com/edsrzf/mmap-go"
	"github.com/mholt/archiver"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() protocols.ProtocolType {
	return protocols.FileProtocol
}

type FileMatch struct {
	Data      string
	Line      int
	ByteIndex int
	Match     bool
	Extract   bool
	Expr      string
	Raw       string
}

var emptyResultErr = errors.New("Empty result")

// processFile handles a single file path: detects archives and processes them
// inline (sequential), or sends regular files to the worker pool channel.
// This helper is used by ExecuteWithResults for archive paths that must be
// handled in the callback goroutine.
func (request *Request) processArchive(filePath string, input *protocols.ScanContext, previous map[string]interface{}, callback protocols.OutputEventCallback) {
	archiveReader, _ := archiver.ByExtension(filePath)
	if archiveReader == nil {
		return
	}
	switch archiveInstance := archiveReader.(type) {
	case archiver.Walker:
		err := archiveInstance.Walk(filePath, func(file archiver.File) error {
			if !request.validatePath("/", file.Name(), true) {
				return nil
			}
			archiveFileName := filepath.Join(filePath, file.Name())
			event, fileMatches, err := request.processReader(file.ReadCloser, archiveFileName, input.Input, file.Size(), previous)
			if err != nil {
				if errors.Is(err, emptyResultErr) {
					return nil
				}
				common.Logger().Debugf("%s\n", err)
				return err
			}
			defer file.Close()
			dumpResponse(event, request.options, fileMatches, filePath)
			callback(event)
			return nil
		})
		if err != nil {
			common.Logger().Debugf("%s\n", err)
		}
	case archiver.Decompressor:
		file, err := os.Open(filePath)
		if err != nil {
			common.Logger().Debugf("%s\n", err)
			return
		}
		defer file.Close()
		fileStat, _ := file.Stat()
		tmpFileOut, err := os.CreateTemp("", "")
		if err != nil {
			common.Logger().Debugf("%s\n", err)
			return
		}
		defer tmpFileOut.Close()
		defer os.RemoveAll(tmpFileOut.Name())
		if err := archiveInstance.Decompress(file, tmpFileOut); err != nil {
			common.Logger().Debugf("%s\n", err)
			return
		}
		_ = tmpFileOut.Sync()
		_, _ = tmpFileOut.Seek(0, 0)
		event, fileMatches, err := request.processReader(tmpFileOut, filePath, input.Input, fileStat.Size(), previous)
		if err != nil {
			if !errors.Is(err, emptyResultErr) {
				common.Logger().Debugf("%s\n", err)
			}
			return
		}
		dumpResponse(event, request.options, fileMatches, filePath)
		callback(event)
	}
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *protocols.ScanContext, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	numWorkers := runtime.NumCPU()
	fileCh := make(chan string, numWorkers*2)

	var cbMu sync.Mutex
	var wg sync.WaitGroup

	// Start worker goroutines for regular (non-archive) file processing.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileCh {
				event, fileMatches, err := request.processFile(filePath, input.Input, previous)
				if err != nil {
					if !errors.Is(err, emptyResultErr) {
						common.Logger().Debugf("%s\n", err)
					}
					continue
				}
				dumpResponse(event, request.options, fileMatches, filePath)
				cbMu.Lock()
				callback(event)
				cbMu.Unlock()
			}
		}()
	}

	err := request.getInputPaths(input.Input, func(filePath string) {
		archiveReader, _ := archiver.ByExtension(filePath)
		if archiveReader != nil {
			// Archives need sequential access – process inline with mutex-protected callback.
			request.processArchive(filePath, input, previous, func(event *protocols.InternalWrappedEvent) {
				cbMu.Lock()
				callback(event)
				cbMu.Unlock()
			})
			return
		}
		// Regular file – send to worker pool.
		fileCh <- filePath
	})

	close(fileCh)
	wg.Wait()

	if err != nil {
		return fmt.Errorf("could not send file request, %s", err)
	}
	return nil
}

func (request *Request) processFile(filePath, input string, previousInternalEvent protocols.InternalEvent) (*protocols.InternalWrappedEvent, []FileMatch, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, nil, emptyResultErr
	}
	if !info.Mode().IsRegular() {
		return nil, nil, emptyResultErr
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, emptyResultErr
	}
	defer file.Close()

	size := info.Size()
	if size >= request.maxSize {
		maxSizeString := common.HumanSize(float64(request.maxSize))
		common.Logger().Debugf("Limiting %s processed data to %s bytes: exceeded max size\n", filePath, maxSizeString)
	}

	const mmapMinSize = 32 * 1024 // 32KB minimum for mmap benefit

	if size >= mmapMinSize && size <= request.maxSize {
		mapped, err := mmap.Map(file, mmap.RDONLY, 0)
		if err == nil {
			defer mapped.Unmap()
			return request.processBytes(mapped, filePath, input, previousInternalEvent)
		}
	}

	return request.processReader(file, filePath, input, size, previousInternalEvent)
}

func (request *Request) processReader(reader io.Reader, filePath, input string, totalBytes int64, previousInternalEvent protocols.InternalEvent) (*protocols.InternalWrappedEvent, []FileMatch, error) {
	fileReader := io.LimitReader(reader, request.maxSize)
	fileMatches, opResult := request.findMatchesWithReader(fileReader, input, filePath, totalBytes, previousInternalEvent)
	if opResult == nil && len(fileMatches) == 0 {
		return nil, nil, emptyResultErr
	}

	// build event structure to interface with internal logic
	return request.buildEvent(input, filePath, fileMatches, opResult, previousInternalEvent), fileMatches, nil
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 && !wrapped.OperatorsResult.Matched {
		return nil
	}

	results := make([]*protocols.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := r.MakeResultEventItem(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := r.MakeResultEventItem(wrapped)
			data.ExtractedResults = v
			data.ExtractorName = k
			results = append(results, data)
		}
	} else {
		data := r.MakeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (request *Request) processBytes(data []byte, filePath, input string, previous protocols.InternalEvent) (*protocols.InternalWrappedEvent, []FileMatch, error) {
	fileMatches, opResult := request.findMatchesWithBytes(data, input, filePath, previous)
	if opResult == nil && len(fileMatches) == 0 {
		return nil, nil, emptyResultErr
	}
	return request.buildEvent(input, filePath, fileMatches, opResult, previous), fileMatches, nil
}

func (request *Request) findMatchesWithBytes(data []byte, input, filePath string, previous protocols.InternalEvent) ([]FileMatch, *operators.Result) {
	var bytesCount, linesCount int
	var fileMatches []FileMatch
	var opResult *operators.Result

	isAND := request.CompiledOperators.GetMatchersCondition() == operators.ANDCondition
	if isAND {
		lineContent := string(data)
		dslMap := request.responseToDSLMap(lineContent, input, filePath)
		for k, v := range previous {
			dslMap[k] = v
		}
		discardEvent := protocols.CreateEvent(request, dslMap)
		return []FileMatch{}, discardEvent.OperatorsResult
	}

	dslMap := request.responseToDSLMap("", input, filePath)
	for k, v := range previous {
		dslMap[k] = v
	}

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

		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if request.prefilter != nil && !request.prefilter.mayMatch(line) {
			linesCount++
			bytesCount += len(line) + 1
			continue
		}

		lineContent := string(line)
		n := len(lineContent)

		dslMap["raw"] = lineContent
		newOpResult := request.quickExecute(dslMap)
		if newOpResult != nil {
			if opResult == nil {
				opResult = newOpResult
			} else {
				mergeOpResult(opResult, newOpResult)
			}
			if newOpResult.Matched || newOpResult.Extracted {
				if newOpResult.Extracts != nil {
					for expr, extracts := range newOpResult.Extracts {
						for _, extract := range extracts {
							fileMatches = append(fileMatches, FileMatch{
								Data:      extract,
								Extract:   true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				if newOpResult.Matches != nil {
					for expr, matches := range newOpResult.Matches {
						for _, match := range matches {
							fileMatches = append(fileMatches, FileMatch{
								Data:      match,
								Match:     true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				for _, outputExtract := range newOpResult.OutputExtracts {
					fileMatches = append(fileMatches, FileMatch{
						Data:      outputExtract,
						Match:     true,
						Line:      linesCount + 1,
						ByteIndex: bytesCount,
						Expr:      outputExtract,
						Raw:       lineContent,
					})
				}
			}
		}

		linesCount++
		bytesCount += n + 1
	}
	return fileMatches, opResult
}

func (request *Request) findMatchesWithReader(reader io.Reader, input, filePath string, totalBytes int64, previous protocols.InternalEvent) ([]FileMatch, *operators.Result) {
	var bytesCount, linesCount, wordsCount int
	//isResponseDebug := request.options.Options.Debug || request.options.Options.DebugResponse
	//totalBytesString := common.BytesSize(float64(totalBytes))

	scanner := bufio.NewScanner(reader)
	buffer := []byte{}
	if request.CompiledOperators.GetMatchersCondition() == operators.ANDCondition {
		scanner.Buffer(buffer, int(defaultMaxReadSize))
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			defaultMaxReadSizeInt := int(defaultMaxReadSize)
			if len(data) > defaultMaxReadSizeInt {
				return defaultMaxReadSizeInt, data[0:defaultMaxReadSizeInt], nil
			}
			if !atEOF {
				return 0, nil, nil
			}
			return len(data), data, bufio.ErrFinalToken
		})
	} else {
		scanner.Buffer(buffer, int(chunkSize))
	}

	var fileMatches []FileMatch
	var opResult *operators.Result

	dslMap := request.responseToDSLMap("", input, filePath)
	for k, v := range previous {
		dslMap[k] = v
	}

	for scanner.Scan() {
		lineContent := scanner.Text()

		if request.prefilter != nil && !request.prefilter.mayMatch([]byte(lineContent)) {
			linesCount += 1 + strings.Count(lineContent, "\n")
			bytesCount += len(lineContent)
			continue
		}

		n := len(lineContent)

		// update counters
		currentBytes := bytesCount + n
		//processedBytes := common.BytesSize(float64(currentBytes))

		//common.NeutronLog.Importantf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytesString)
		dslMap["raw"] = lineContent
		newOpResult := request.quickExecute(dslMap)
		if newOpResult != nil {
			if opResult == nil {
				opResult = newOpResult
			} else {
				mergeOpResult(opResult, newOpResult)
			}
			if newOpResult.Matched || newOpResult.Extracted {
				if newOpResult.Extracts != nil {
					for expr, extracts := range newOpResult.Extracts {
						for _, extract := range extracts {
							fileMatches = append(fileMatches, FileMatch{
								Data:      extract,
								Extract:   true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				if newOpResult.Matches != nil {
					for expr, matches := range newOpResult.Matches {
						for _, match := range matches {
							fileMatches = append(fileMatches, FileMatch{
								Data:      match,
								Match:     true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				for _, outputExtract := range newOpResult.OutputExtracts {
					fileMatches = append(fileMatches, FileMatch{
						Data:      outputExtract,
						Match:     true,
						Line:      linesCount + 1,
						ByteIndex: bytesCount,
						Expr:      outputExtract,
						Raw:       lineContent,
					})
				}
			}
		}

		currentLinesCount := 1 + strings.Count(lineContent, "\n")
		linesCount += currentLinesCount
		wordsCount += strings.Count(lineContent, " ")
		bytesCount = currentBytes
	}
	return fileMatches, opResult
}

func (request *Request) buildEvent(input, filePath string, fileMatches []FileMatch, operatorResult *operators.Result, previous protocols.InternalEvent) *protocols.InternalWrappedEvent {
	exprLines := make(map[string][]int)
	exprBytes := make(map[string][]int)
	internalEvent := request.responseToDSLMap("", input, filePath)
	for k, v := range previous {
		internalEvent[k] = v
	}
	for _, fileMatch := range fileMatches {
		exprLines[fileMatch.Expr] = append(exprLines[fileMatch.Expr], fileMatch.Line)
		exprBytes[fileMatch.Expr] = append(exprBytes[fileMatch.Expr], fileMatch.ByteIndex)
	}

	event := protocols.CreateEventWithOperatorResults(request, internalEvent, operatorResult)
	// Annotate with line numbers if asked by the user
	// todo
	//if request.options.Options.ShowMatchLine {
	//	for _, result := range event.Results {
	//		switch {
	//		case result.MatcherName != "":
	//			result.Lines = exprLines[result.MatcherName]
	//		case result.ExtractorName != "":
	//			result.Lines = exprLines[result.ExtractorName]
	//		default:
	//			for _, extractedResult := range result.ExtractedResults {
	//				result.Lines = append(result.Lines, exprLines[extractedResult]...)
	//			}
	//		}
	//		result.Lines = sliceutil.DedupeInt(result.Lines)
	//	}
	//}
	return event
}

func mergeOpResult(dst, src *operators.Result) {
	if src.Matched {
		dst.Matched = true
	}
	if src.Extracted {
		dst.Extracted = true
	}
	for k, v := range src.Matches {
		if dst.Matches == nil {
			dst.Matches = make(map[string][]string)
		}
		dst.Matches[k] = append(dst.Matches[k], v...)
	}
	for k, v := range src.Extracts {
		if dst.Extracts == nil {
			dst.Extracts = make(map[string][]string)
		}
		dst.Extracts[k] = append(dst.Extracts[k], v...)
	}
	dst.OutputExtracts = append(dst.OutputExtracts, src.OutputExtracts...)
}

func dumpResponse(event *protocols.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, filematches []FileMatch, filePath string) {
	//cliOptions := requestOptions.Options
	//if cliOptions.Debug || cliOptions.DebugResponse {
	//	for _, fileMatch := range filematches {
	//		lineContent := fileMatch.Raw
	//		hexDump := false
	//		if responsehighlighter.HasBinaryContent(lineContent) {
	//			hexDump = true
	//			lineContent = hex.Dump([]byte(lineContent))
	//		}
	//		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, lineContent, cliOptions.NoColor, hexDump)
	//		common.Logger().Debugf("[%s] Dumped match/extract file snippet for %s at line %d\n\n%s", requestOptions.TemplateID, filePath, fileMatch.Line, highlightedResponse)
	//	}
	//}
}
