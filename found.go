package main

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/chainreactors/found/cmd"
	"github.com/jessevdk/go-flags"
)

func main() {
	var opts cmd.Options
	parser := flags.NewParser(&opts, flags.Default)
	parser.Name = "found"
	parser.Usage = `[OPTIONS] -i <target>

Examples:
  found -i ~/projects                        Scan with default key templates
  found -i ~/projects -c keys,logs           Scan with keys + logs templates
  found -i ~/projects --text-only            Skip binary files (faster)
  found -i ~/projects --severity high        Only show high severity findings
  found -i ~/projects -o json -s out.json    Save JSON results to file
  found -i ~/projects -t my-rules.yaml       Use custom template file
  found --list                               List available templates
  found --list -c logs                       List templates in logs category`

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Profile != "" {
		f, err := os.Create(opts.Profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] cannot create profile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if err := cmd.Run(&opts); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}
}
