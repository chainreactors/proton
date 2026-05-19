//go:generate go run chainreactors-templates/templates_gen.go -t chainreactors-templates -o pkg/templates.go -need found
package main

import (
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
  found --auto --collect findings.zip -k pw  Auto-scan and package results
  found -i ~/projects --severity high        Only show high severity findings
  found -i ~/projects -j -s out.json         Save JSON results to file
  found -i ~/projects -t my-rules.yaml       Use custom template file
  found --list                               List available templates`

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if err := cmd.Run(&opts); err != nil {
		logs.Log.Errorf("%v", err)
		os.Exit(1)
	}
}
