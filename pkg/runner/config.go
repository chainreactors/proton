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
	Listen    string
	BPFFilter string
	Severity  string
	MaxSize   string

	// Process
	PID           int
	Process       string
	Mem           bool
	MemAll        bool
	Env           bool
	Cmdline       bool
	Fd            bool
	Conn          bool
	Pipe          bool
	Registry      bool
	RegistryHives []string

	// Filesystem scope
	Config   bool
	Home     bool
	Docker   bool
	Logs     bool
	History  bool
	Tmpfs    bool
	Git      bool
	Coredump  bool
	Keyring   bool
	Clipboard bool
	Keylog    bool

	Input       string
	TemplateDir string
	Baseline    string
	Findings    string
	FailOn      string
}

func (c *Config) ProcessScanEnabled() bool {
	return c.PID != 0 || c.Process != "" || c.Mem || c.Env || c.Cmdline || c.Fd || c.Conn || c.Pipe
}

func (c *Config) RegistryScanEnabled() bool {
	return c.Registry || len(c.RegistryHives) > 0
}

func (c *Config) ProcessSources() []string {
	var sources []string
	if c.Env {
		sources = append(sources, "env")
	}
	if c.Cmdline {
		sources = append(sources, "cmdline")
	}
	if c.Fd {
		sources = append(sources, "fd")
	}
	if c.Conn {
		sources = append(sources, "conn")
	}
	if c.Pipe {
		sources = append(sources, "pipe")
	}
	if len(sources) == 0 && !c.Mem {
		if c.PID != 0 || c.Process != "" {
			return []string{"env", "cmdline", "fd", "conn", "pipe"}
		}
	}
	return sources
}
