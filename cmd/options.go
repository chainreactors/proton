package cmd

type Options struct {
	InputOptions  `group:"Input Options"`
	OutputOptions `group:"Output Options"`
	ScanOptions   `group:"Scan Options"`
}

type InputOptions struct {
	Input            string   `short:"i" long:"input" description:"target file or directory to scan"`
	Templates        []string `short:"t" long:"template" description:"template file or directory path (can specify multiple)"`
	ExcludeTemplates []string `long:"exclude-template" description:"template file or directory to exclude (can specify multiple)"`
	Categories       []string `short:"c" long:"category" description:"builtin template categories, e.g. keys,logs" default:"keys"`
	TemplateIDs      []string `long:"id" description:"filter templates by ID (can specify multiple)"`
	ExcludeIDs       []string `long:"exclude-id" description:"exclude templates by ID (can specify multiple)"`
	Tags             []string `long:"tags" description:"filter templates by tags (comma-separated in template)"`
	ExcludeTags      []string `long:"etags" description:"exclude templates by tags"`
	Expressions      []string `short:"e" long:"expression" description:"regex pattern to search directly (like ripgrep, can specify multiple)"`
	ExtFilter        string   `long:"ext" description:"comma-separated file extensions for -e mode (e.g. .go,.py)"`
}

type OutputOptions struct {
	Output   string `short:"o" long:"output" description:"output format: text, json" default:"text" choice:"text" choice:"json"`
	JSON     bool   `short:"j" long:"json" description:"shorthand for -o json (jsonlines to stdout)"`
	SaveFile string `short:"s" long:"save" description:"save results to file"`
	Collect     string `long:"collect" description:"collect matched files into a zip archive (e.g. --collect findings.zip)"`
	CollectTree bool   `long:"collect-tree" description:"preserve directory structure in collect zip (default: flat)"`
	Key         string `short:"k" long:"key" description:"password for the collect zip archive"`
	Quiet    bool   `short:"q" long:"quiet" description:"only print findings, no banner or stats"`
}

type ScanOptions struct {
	Auto        bool   `long:"auto" description:"auto-detect OS and scan common sensitive directories"`
	Bin         bool   `long:"bin" description:"include binary files in scan (default: text-only)"`
	Severity    string `long:"severity" description:"filter by severity, comma-separated (critical,high,medium,low,info)"`
	MaxSize     string `long:"max-size" description:"max file size to process" default:"1Gb"`
	TemplateDir string `long:"template-dir" description:"nuclei file templates root directory" default:"/tmp/nuclei-templates/file"`
	List        bool   `long:"list" description:"list available templates and exit"`
}
