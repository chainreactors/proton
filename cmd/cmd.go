package cmd

import (
	"github.com/chainreactors/proton/pkg/runner"
)

const Version = runner.Version

func Run(opts *Options) error {
	if opts.UpdateTemplates {
		return runUpdateTemplates(opts)
	}
	if opts.Validate {
		return runValidate(opts)
	}
	if opts.Display != "" {
		return runTemplateDisplay(opts)
	}
	if opts.List {
		return listTemplates(opts)
	}

	cfg := &runner.Config{
		Templates:        opts.Templates,
		ExcludeTemplates: opts.ExcludeTemplates,
		Categories:       opts.Categories,
		TemplateIDs:      opts.TemplateIDs,
		ExcludeIDs:       opts.ExcludeIDs,
		Tags:             opts.Tags,
		ExcludeTags:      opts.ExcludeTags,
		Expressions:      opts.Expressions,
		ExtFilter:        opts.ExtFilter,
		IgnoreFiles:      opts.IgnoreFiles,

		Output:      opts.Output,
		JSON:        opts.JSON,
		SaveFile:    opts.SaveFile,
		Collect:     opts.Collect,
		CollectTree: opts.CollectTree,
		Quiet:       opts.Quiet,
		NoColor:     opts.NoColor,

		Auto:      opts.Auto,
		Bin:       opts.Bin,
		Listen:    opts.Listen,
		BPFFilter: opts.BPFFilter,
		Severity:  opts.Severity,

		PID:           opts.PID,
		Process:       opts.Process,
		Mem:           opts.Mem,
		MemAll:        opts.MemAll,
		Env:           opts.Env,
		Cmdline:       opts.Cmdline,
		Fd:            opts.Fd,
		Conn:          opts.Conn,
		Pipe:          opts.Pipe,
		Registry:      opts.Registry,
		RegistryHives: opts.RegistryHives,

		Config:   opts.Config,
		Home:     opts.Home,
		Docker:   opts.Docker,
		Logs:     opts.Logs,
		History:  opts.History,
		Browser:  opts.Browser,
		Tmpfs:    opts.Tmpfs,
		Git:      opts.Git,
		Coredump: opts.Coredump,
		Keyring:  opts.Keyring,

		TemplateDir: opts.TemplateDir,
		Baseline:    opts.Baseline,
		Findings:    opts.Findings,
		FailOn:      opts.FailOn,
		Input:       opts.Input,
	}

	r, err := runner.New(cfg)
	if err != nil {
		return err
	}
	return r.Run()
}

type ExitError = runner.ExitError
