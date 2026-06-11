package runner

type Config struct {
	// Input
	Input            string
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
	TemplateDir      string

	// Scope: process
	PID     int
	Process string
	Mem     bool
	MemAll  bool
	Env     bool
	Cmdline bool
	Fd      bool
	Conn    bool
	Pipe    bool

	// Scope: filesystem
	Config   bool
	Home     bool
	Docker   bool
	Logs     bool
	History  bool
	Tmpfs    bool
	Git      bool
	Coredump bool

	// Scope: system
	Keyring       bool
	Registry      bool
	RegistryHives []string

	// Scope: live monitoring
	Listen    string
	BPFFilter string
	Clipboard bool
	Keylog    bool

	// Output
	Output      string
	JSON        bool
	SaveFile    string
	Collect     string
	CollectTree bool
	Quiet       bool
	NoColor     bool
	Bin         bool
	Auto        bool
	Severity    string
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
