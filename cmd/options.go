package cmd

type Options struct {
	InputOptions  `group:"Input Options"`
	OutputOptions `group:"Output Options"`
	ScanOptions   `group:"Scan Options"`
}

type InputOptions struct {
	Input      string   `short:"i" long:"input" description:"target file or directory to scan"`
	Templates  []string `short:"t" long:"template" description:"template file or directory path (can specify multiple)"`
	Categories []string `short:"c" long:"category" description:"builtin template categories, e.g. keys,logs" default:"keys"`
	Tags       []string `long:"tags" description:"filter templates by tags"`
}

type OutputOptions struct {
	Output   string `short:"o" long:"output" description:"output format: text, json" default:"text" choice:"text" choice:"json"`
	SaveFile string `short:"s" long:"save" description:"save results to file"`
	Quiet    bool   `short:"q" long:"quiet" description:"only print findings, no banner or stats"`
}

type ScanOptions struct {
	Bin         bool   `long:"bin" description:"include binary files in scan (default: text-only)"`
	Severity    string `long:"severity" description:"filter by severity, comma-separated (critical,high,medium,low,info)"`
	MaxSize     string `long:"max-size" description:"max file size to process" default:"1Gb"`
	TemplateDir string `long:"template-dir" description:"nuclei file templates root directory" default:"/tmp/nuclei-templates/file"`
	List        bool   `long:"list" description:"list available templates and exit"`
	Profile     string `long:"profile" description:"enable CPU profiling, write to given file path (e.g. cpu.prof)"`
}
