package cmd

type Options struct {
	InputOptions    `group:"Input Options"`
	OutputOptions   `group:"Output Options"`
	ScanOptions     `group:"Scan Options"`
	ProcessOptions  `group:"Process Scan Options"`
	TemplateOptions `group:"Template Management"`
	Version         bool `long:"version" description:"print version and exit"`
}

type InputOptions struct {
	Input            string   `short:"i" long:"input" description:"target file or directory to scan"`
	Templates        []string `short:"t" long:"template" description:"template file or directory path (can specify multiple)"`
	ExcludeTemplates []string `long:"exclude-template" description:"template file or directory to exclude (can specify multiple)"`
	Categories       []string `short:"c" long:"category" description:"builtin template categories, e.g. keys,spray" default:"keys"`
	TemplateIDs      []string `long:"id" description:"filter templates by ID (can specify multiple)"`
	ExcludeIDs       []string `long:"exclude-id" description:"exclude templates by ID (can specify multiple)"`
	Tags             []string `long:"tags" description:"filter templates by tags (comma-separated in template)"`
	ExcludeTags      []string `long:"etags" description:"exclude templates by tags"`
	Expressions      []string `short:"e" long:"expression" description:"regex pattern to search directly (like ripgrep, can specify multiple)"`
	ExtFilter        string   `long:"ext" description:"comma-separated file extensions for -e mode (e.g. .go,.py)"`
	IgnoreFiles      []string `long:"ignore" description:"suppress reviewed findings via ignore rules (.foundignore.yaml)"`
}

type OutputOptions struct {
	Output      string `short:"o" long:"output" description:"output format: text, json, zombie" default:"text" choice:"text" choice:"json" choice:"zombie"`
	JSON        bool   `short:"j" long:"json" description:"shorthand for -o json (jsonlines to stdout)"`
	SaveFile    string `short:"s" long:"save" description:"save results to file"`
	Collect     string `long:"collect" description:"collect matched files into a zip archive (e.g. --collect findings.zip)"`
	CollectTree bool   `long:"collect-tree" description:"preserve directory structure in collect zip (default: flat)"`
	Quiet       bool   `short:"q" long:"quiet" description:"only print findings, no banner or stats"`
	NoColor     bool   `long:"no-color" description:"disable colored output"`
}

type ScanOptions struct {
	Auto        bool   `long:"auto" description:"auto-detect OS and scan common sensitive directories"`
	Bin         bool   `long:"bin" description:"include binary files in scan (default: text-only)"`
	Listen      string `long:"listen" description:"capture live traffic on network interface"`
	BPFFilter   string `long:"bpf" description:"packet filter (e.g. 'port 80')"`
	Severity    string `long:"severity" description:"filter by severity, comma-separated (critical,high,medium,low,info)"`
	MaxSize     string `long:"max-size" description:"max file size to process" default:"1Gb"`
	TemplateDir string `long:"template-dir" description:"nuclei file templates root directory" default:"/tmp/nuclei-templates/file"`
	List        bool   `long:"list" description:"list available templates and exit"`
	Validate    bool   `long:"validate" description:"validate templates and exit"`
	Display     string `short:"d" long:"template-display" description:"display template content by ID or file path"`
	Baseline    string `long:"baseline" description:"load baseline file to suppress known findings"`
	Findings    string `short:"f" long:"findings" description:"save findings in baseline format (can be used as future --baseline input)"`
	FailOn      string `long:"fail-on" description:"exit with code 1 if findings match severity (e.g. high,critical)"`
}

type ProcessOptions struct {
	PID     int    `long:"pid" description:"scan a specific process by PID (0 = all accessible processes)"`
	Process string `long:"process" description:"scan processes matching name substring"`
	Mem     bool   `long:"mem" description:"scan process memory regions"`
	MemAll  bool   `long:"mem-all" description:"scan ALL readable memory regions (default: writable/anonymous only)"`
	Env     bool   `long:"env" description:"scan process environment variables"`
	Cmdline bool   `long:"cmdline" description:"scan process command-line arguments"`
	Fd      bool   `long:"fd" description:"scan process open file descriptors"`
	Conn    bool   `long:"conn" description:"scan process network connections"`
	Pipe    bool   `long:"pipe" description:"scan process named pipes"`
}

type TemplateOptions struct {
	UpdateTemplates   bool   `long:"update-templates" description:"download or update templates from a git repository"`
	TemplateURL       string `long:"template-url" description:"custom template repository URL (saved to config)"`
	UpdateTemplateDir string `long:"update-template-dir" description:"custom directory for template installation (default: ~/.config/found/templates)"`
}
