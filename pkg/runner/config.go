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

	// Process targeting
	PID     int
	Process string

	// Process data sources
	Mem     bool
	MemAll  bool
	Env     bool
	Cmdline bool
	Fd      bool
	Conn    bool
	Pipe    bool

	// System-level sources
	Shm     bool
	Tmpfs   bool
	History bool
	Keyring bool

	Input       string
	TemplateDir string
	Baseline    string
	Findings    string
	FailOn      string
}

// ProcessScanEnabled returns true if any process-level scan flag is set.
func (c *Config) ProcessScanEnabled() bool {
	return c.PID != 0 || c.Process != "" || c.Mem || c.Env || c.Cmdline || c.Fd || c.Conn || c.Pipe
}

// ProcessSources returns the list of sysinfo source names to scan.
// If no specific source flag is set but PID/Process is given, defaults to all sources.
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

// ScopeScanEnabled returns true if any system-level scope flag is set.
func (c *Config) ScopeScanEnabled() bool {
	return c.Shm || c.Tmpfs || c.History || c.Keyring
}
