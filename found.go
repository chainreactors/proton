//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go -need found -embed
package main

import (
	"fmt"
	"os"

	"github.com/chainreactors/found/cmd"
	"github.com/chainreactors/logs"
	"github.com/jessevdk/go-flags"
)

func main() {
	var opts cmd.Options
	parser := flags.NewParser(&opts, flags.Default)
	parser.Name = "found"
	parser.Usage = `[OPTIONS] -i <target>

Examples:
  found -i ~/projects                        Scan with default key templates
  found --auto                               Auto-detect OS and scan sensitive dirs
  found --auto --collect findings.zip         Auto-scan and package results
  found -i ~/projects --severity high        Only show high severity findings
  found -i ~/projects -j -s out.json         Save JSON results to file
  found -i ~/projects -t my-rules.yaml       Use custom template file
  found --list                               List available templates
  found --validate -t my-rules/              Validate template files
  found --update-templates --template-url <repo>  Install templates from git repo
  found --update-templates                   Update previously installed templates`

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Version {
		fmt.Println("found " + cmd.Version)
		os.Exit(0)
	}

	if err := cmd.Run(&opts); err != nil {
		logs.Log.Errorf("%v", err)
		os.Exit(1)
	}
}
