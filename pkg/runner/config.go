package runner

type Config struct {
	Targets          []string
	Templates        []string
	ExcludeTemplates []string
	Categories       []string
	TemplateIDs      []string
	ExcludeIDs       []string
	Tags             []string
	ExcludeTags      []string
	Expressions      []string
	ExtFilter        string
	IgnoreFiles      []string

	Output      string
	JSON        bool
	SaveFile    string
	Collect     string
	CollectTree bool
	Quiet       bool
	NoColor     bool

	Auto      bool
	Bin       bool
	PID       int
	MemAll    bool
	Listen    string
	BPFFilter string
	Severity  string
	MaxSize   string

	Input       string
	TemplateDir string
	Baseline    string
	Findings    string
	FailOn      string
}
