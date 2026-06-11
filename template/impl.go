package template

import (
	"errors"
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
)

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}
}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	if options == nil {
		options = &protocols.ExecuterOptions{Options: &protocols.Options{}}
	}

	if len(t.RequestsFile) > 0 {
		for _, req := range t.RequestsFile {
			if err := req.Compile(options); err != nil {
				return err
			}
		}
		inputs := []file.Rule{{
			ID:       t.Id,
			Name:     t.Info.Name,
			Severity: t.Info.Severity,
			Requests: t.RequestsFile,
		}}
		t.scanner = file.NewScanner(inputs, options)
		t.TotalRequests = len(t.RequestsFile)
	}

	if len(t.RequestsFile) == 0 && len(t.RequestsSysRaw) == 0 {
		return errors.New("no requests defined in template")
	}
	return nil
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if len(t.RequestsFile) == 0 {
		return nil, errors.New("template not compiled or has no file requests")
	}

	scanCtx := protocols.NewScanContext(input, payload)
	var merged *operators.Result

	for _, req := range t.RequestsFile {
		err := req.ExecuteWithResults(scanCtx, nil, nil, func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult == nil {
				return
			}
			if !event.OperatorsResult.Matched && !event.OperatorsResult.Extracted {
				return
			}
			if merged == nil {
				merged = event.OperatorsResult
			} else {
				mergeResult(merged, event.OperatorsResult)
			}
		})
		if err != nil {
			return nil, err
		}
	}

	if merged == nil {
		return &operators.Result{}, nil
	}
	return merged, nil
}

func (t *Template) ScanData(data []byte, label string) []file.Finding {
	if t.scanner == nil {
		return nil
	}
	var findings []file.Finding
	for _, group := range t.scanner.Groups {
		findings = append(findings, t.scanner.ScanData(data, label, group)...)
	}
	return findings
}

func (t *Template) ScanBlock(data []byte, label string) []file.Finding {
	if t.scanner == nil {
		return nil
	}
	var findings []file.Finding
	for _, group := range t.scanner.Groups {
		findings = append(findings, t.scanner.ScanBlock(data, label, group)...)
	}
	return findings
}

func mergeResult(dst, src *operators.Result) {
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
