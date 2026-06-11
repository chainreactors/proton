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
	Paths   []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	Hives   []string `json:"hives,omitempty" yaml:"hives,omitempty"`

	MaxDepth      int  `json:"max_depth,omitempty" yaml:"max-depth,omitempty"`
	MaxKeys       int  `json:"max_keys,omitempty" yaml:"max-keys,omitempty"`
	MaxValues     int  `json:"max_values,omitempty" yaml:"max-values,omitempty"`
	MaxValueBytes int  `json:"max_value_bytes,omitempty" yaml:"max-value-bytes,omitempty"`
	IncludeBinary bool `json:"include_binary,omitempty" yaml:"include-binary,omitempty"`

	CompiledOperators *operators.Operators `json:"-" yaml:"-"`
	regions           map[string]struct{}
	registryTargets   []sysinfo.RegistryTarget
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
	r.registryTargets = nil
	if r.Source == sysinfo.SourceRegistry {
		for _, path := range r.Paths {
			target, err := sysinfo.ParseRegistryTarget(path, r.MaxDepth)
			if err != nil {
				return err
			}
			r.registryTargets = append(r.registryTargets, target)
		}
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

func (r *Request) RegistryOptions() sysinfo.RegistryWalkOptions {
	opts := sysinfo.DefaultRegistryWalkOptions()
	opts.Targets = append([]sysinfo.RegistryTarget(nil), r.registryTargets...)
	opts.Hives = append([]string(nil), r.Hives...)
	if len(r.registryTargets) == 0 && len(r.Hives) == 0 {
		opts.Targets = sysinfo.DefaultRegistryTargets()
	}
	if len(r.registryTargets) == 0 && len(r.Hives) > 0 {
		opts.Targets = nil
	}
	if r.MaxDepth > 0 {
		opts.MaxDepth = r.MaxDepth
	}
	if r.MaxKeys > 0 {
		opts.MaxKeys = r.MaxKeys
	}
	if r.MaxValues > 0 {
		opts.MaxValues = r.MaxValues
	}
	if r.MaxValueBytes > 0 {
		opts.MaxValueBytes = r.MaxValueBytes
	}
	opts.IncludeBinary = r.IncludeBinary
	return opts
}
