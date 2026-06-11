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

	if len(t.RequestsSys) > 0 {
		for _, req := range t.RequestsSys {
			if err := req.Compile(options); err != nil {
				return err
			}
		}
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

	if len(t.RequestsFile) == 0 && len(t.RequestsSys) == 0 {
		return errors.New("no requests defined in template")
	}
	return nil
}

// Execute runs this template against input (a file or directory path) and
// returns the aggregated operator result. Uses the Scanner engine internally.
func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.scanner == nil {
		return nil, errors.New("template not compiled or has no file requests")
	}

	var merged *operators.Result

	for _, group := range t.scanner.Groups {
		contents := t.scanner.ReadFile(input, group)
		for _, c := range contents {
			findings := t.scanner.ScanData(c.Data, c.Label, group)
			for _, f := range findings {
				if f.Result == nil {
					continue
				}
				if merged == nil {
					merged = f.Result
				} else {
					mergeResult(merged, f.Result)
				}
			}
		}
	}

	if merged == nil {
		return &operators.Result{}, nil
	}
	return merged, nil
}

// ScanData runs this template's scanner against in-memory data and returns findings.
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

// ScanBlock runs this template's scanner against binary data and returns findings.
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
