package sys

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/sysinfo"
)

type Request struct {
	operators.Operators `json:",inline" yaml:",inline"`

	Source  string   `json:"source,omitempty" yaml:"source,omitempty"`
	Process string   `json:"process,omitempty" yaml:"process,omitempty"`
	Regions []string `json:"regions,omitempty" yaml:"regions,omitempty"`

	CompiledOperators *operators.Operators `json:"-" yaml:"-"`
	regions           map[string]struct{}
}

func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return fmt.Errorf("could not compile sys operators: %s", err)
		}
		r.CompiledOperators = compiled
	}

	if r.Source == "" {
		r.Source = sysinfo.SourceMemory
	}

	r.regions = make(map[string]struct{})
	for _, region := range r.Regions {
		r.regions[strings.ToLower(region)] = struct{}{}
	}
	if r.Source == sysinfo.SourceMemory && len(r.regions) == 0 {
		r.regions["heap"] = struct{}{}
		r.regions["stack"] = struct{}{}
		r.regions["anonymous"] = struct{}{}
	}
	return nil
}

func (r *Request) MatchesProcess(name string) bool {
	if r.Process == "" {
		return true
	}
	return strings.Contains(strings.ToLower(name), strings.ToLower(r.Process))
}

func (r *Request) MatchesRegion(perms, mappedFile string) bool {
	if _, ok := r.regions["all"]; ok {
		return strings.Contains(perms, "r")
	}
	if !strings.Contains(perms, "r") {
		return false
	}
	if _, ok := r.regions["heap"]; ok && mappedFile == "[heap]" {
		return true
	}
	if _, ok := r.regions["stack"]; ok && mappedFile == "[stack]" {
		return true
	}
	if _, ok := r.regions["anonymous"]; ok && (mappedFile == "" || strings.HasPrefix(mappedFile, "[")) {
		return true
	}
	if _, ok := r.regions["writable"]; ok && strings.Contains(perms, "w") {
		return true
	}
	return false
}

func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}
