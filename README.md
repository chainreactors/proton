# proton

High-performance content scanning engine for detecting leaked credentials, API keys, private keys, and other sensitive information — in files, process memory, environment variables, and live network traffic.

## Architecture

```
proton/
├── sysinfo/        # standalone Go module — data acquisition layer
│   ├── process     # enumerate processes, read env/cmdline/fd/conn/pipe
│   ├── memory      # cross-platform process memory reading
│   ├── capture     # raw network packet capture (Linux/macOS/Windows)
│   ├── stream      # TCP stream reassembly
│   └── packet      # Ethernet/IPv4/TCP parsing
├── proton/file/    # scanning engine — prefilter → Aho-Corasick → RE2
├── proton/sys/     # sys protocol — targeted process scan templates
├── pkg/runner/     # scan orchestration — Runner API, templates, output
└── cmd/            # CLI shell (found)
```

Three layers:

- **sysinfo** — independent Go module (`sysinfo/go.mod`), zero proton dependency. Reads data from processes, memory, and network. Usable standalone.
- **proton/file** — scanning engine with three-layer pipeline (prefilter → Aho-Corasick DFA → RE2). Importable as a library.
- **found** (CLI) / **pkg/runner** — scan orchestration, template management, output formatting. `pkg/runner` exposes a programmatic `Runner` API.

### Scanning Pipeline

Each line passes through progressively expensive layers, skipping work as early as possible:

1. **Prefilter** — `bytes.Contains` on raw `[]byte`, zero allocation (~4ns/line)
2. **Aho-Corasick DFA** — multi-pattern index, selects relevant regex subset per line
3. **RE2 regex** — only runs patterns identified by the previous layer (8.4x faster than Go stdlib)

## Installation

```bash
go install github.com/chainreactors/proton@latest
```

Or build from source:

```bash
git clone https://github.com/chainreactors/proton
cd proton
go build -o found .
```

## Quick Start

```bash
# Scan a directory with built-in key-detection templates
found -i ~/projects

# Auto-detect OS and scan common sensitive directories
found --auto

# Search with regex directly (like ripgrep)
found -i ~/projects -e "AKIA[0-9A-Z]{16}"

# Scan process environment variables for secrets
found --pid 1234 --env

# Scan all processes matching a name
found --process nginx --env --cmdline

# Scan process memory
found --pid 1234 --mem

# Capture and scan live network traffic
found --listen eth0

# Output as JSON
found -i ~/projects -j -s results.json
```

## Data Sources

found scans across multiple data sources using the same templates:

| Source | Flag | Description |
|--------|------|-------------|
| **Files** | `-i <path>` | Local files and directories (archives auto-extracted) |
| **Memory** | `--mem` | Process virtual memory regions |
| **Env** | `--env` | Process environment variables |
| **Cmdline** | `--cmdline` | Process command-line arguments |
| **FD** | `--fd` | Open file descriptors |
| **Connections** | `--conn` | Network connections |
| **Pipes** | `--pipe` | Named pipes |
| **Network** | `--listen <iface>` | Live traffic capture with TCP stream reassembly |

## Process Scanning

```bash
# Scan a specific PID — defaults to all data sources (env, cmdline, fd, conn, pipe)
found --pid 1234

# Scan only specific sources
found --pid 1234 --env --cmdline

# Add memory scanning
found --pid 1234 --mem

# Scan all readable memory regions (including mapped libraries)
found --pid 1234 --mem-all

# Scan all processes matching a name
found --process sshd --env

# Scan all accessible processes
found --pid 0 --env
```

### sys: Protocol Templates

For targeted process scanning with process/region filtering:

```yaml
id: chrome-secrets
info:
  name: Chrome Process Secret Scanner
  severity: high

sys:
  - source: memory
    process: chrome
    regions: [heap, stack, anonymous]
    extractors:
      - type: regex
        regex:
          - "password[=:]\\S+"

  - source: env
    process: sshd
    extractors:
      - type: regex
        regex:
          - "(?i)(?:password|secret|token)=\\S+"
```

## Network Scanning

```bash
# Capture and scan all traffic on an interface
found --listen eth0

# Filter by port
found --listen eth0 --bpf "port 80"

# Scan with custom regex
found --listen eth0 -e "password=\S+"
```

TCP streams are reassembled before scanning — matches spanning multiple packets are detected.

## Using as a Library

### proton/file — Scanning Engine

```go
import (
    "github.com/chainreactors/proton/proton/file"
    "github.com/chainreactors/neutron/protocols"
)

scanner := file.NewScanner(rules, execOpts)
scanner.Scan("/path/to/target", func(f file.Finding) {
    fmt.Printf("[%s] %s: %s\n", f.Severity, f.TemplateID, f.FilePath)
})
```

### sysinfo — Data Acquisition (standalone module)

```go
import "github.com/chainreactors/proton/sysinfo"

// Read process environment
env, _ := sysinfo.ReadProcessEnv(pid)

// Walk process memory
sysinfo.WalkProcessMemory(pid, sysinfo.MemScanOptions{}, func(data []byte, label string) {
    // scan data chunk
})

// TCP stream reassembly
reassembler := sysinfo.NewStreamReassembler(func(data []byte, label string) {
    // scan reassembled stream data
}, overlapSize, windowSize)
reassembler.ProcessPacket(pkt)

// Enumerate processes
procs, _ := sysinfo.ListProcesses()
```

### pkg/runner — Programmatic Runner

```go
import "github.com/chainreactors/proton/pkg/runner"

cfg := &runner.Config{
    Input:      "/path/to/scan",
    Categories: []string{"keys"},
    Quiet:      true,
    Output:     "json",
}
r, _ := runner.New(cfg)
r.Run()
```

## CLI Reference

### Input Options

| Flag | Short | Description |
|------|-------|-------------|
| `--input` | `-i` | Target file or directory to scan |
| `--auto` | | Auto-detect OS and scan common sensitive directories |
| `--template` | `-t` | Template file or directory (can specify multiple) |
| `--exclude-template` | | Template to exclude |
| `--category` | `-c` | Template categories (default: `keys`) |
| `--id` | | Filter templates by ID |
| `--exclude-id` | | Exclude templates by ID |
| `--tags` | | Include only templates matching tags |
| `--etags` | | Exclude templates matching tags |
| `--expression` | `-e` | Regex pattern to search directly |
| `--ext` | | File extensions filter for `-e` mode |
| `--ignore` | | Ignore rules file (.foundignore.yaml) |

### Output Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Format: `text`, `json`, `zombie` (default: `text`) |
| `--json` | `-j` | Shorthand for `-o json` |
| `--save` | `-s` | Save results to file |
| `--collect` | | Collect matched files into zip |
| `--collect-tree` | | Preserve directory structure in zip |
| `--quiet` | `-q` | Only print findings |
| `--no-color` | | Disable colored output |

### Scan Options

| Flag | Description |
|------|-------------|
| `--bin` | Include binary files (default: text-only) |
| `--listen` | Capture live traffic on network interface |
| `--bpf` | BPF packet filter (e.g. `port 80`) |
| `--severity` | Filter by severity (`critical,high,medium,low,info`) |
| `--baseline` | Suppress known findings from baseline file |
| `--findings` | Save findings as baseline |
| `--fail-on` | Exit code 1 if findings match severity |

### Process Scan Options

| Flag | Description |
|------|-------------|
| `--pid` | Scan specific PID (0 = all accessible processes) |
| `--process` | Scan processes matching name substring |
| `--mem` | Scan process memory regions |
| `--mem-all` | Scan ALL readable memory regions |
| `--env` | Scan environment variables |
| `--cmdline` | Scan command-line arguments |
| `--fd` | Scan open file descriptors |
| `--conn` | Scan network connections |
| `--pipe` | Scan named pipes |

### Template Management

| Flag | Description |
|------|-------------|
| `--list` | List available templates |
| `--validate` | Validate template files |
| `--template-display` | Display template content |
| `--update-templates` | Download/update templates from git |
| `--template-url` | Custom template repository URL |

## Template Format

```yaml
id: aws-credentials
info:
  name: AWS Credentials Detection
  severity: critical
  tags: cloud,aws

file:
  - extensions:
      - all
    matchers:
      - type: word
        words:
          - "AKIA"
    extractors:
      - type: regex
        regex:
          - "AKIA[0-9A-Z]{16}"
```

## Benchmark

Intel Core Ultra 9 285H, 156 built-in templates (863 regex patterns), real source files.

| Data | Files | proton | naive | Speedup |
|------|-------|--------|-------|---------|
| 1 KB | 1 | 151 µs | 4 ms | **28x** |
| 1 MB | 137 | 362 µs | 18.4 s | **50,000x** |
| 1 GB | 162,258 | 34 ms | ~5h (projected) | **540,000x** |

### File Filtering

| Category | Examples | Behavior |
|----------|---------|----------|
| **Media/Font** | .png .jpg .mp4 .ttf .woff | Always skipped |
| **Executable** | .exe .dll .so .class .pyc | Skipped; `--bin` to include |
| **Archive** | .tar .gz .zip .7z .rar | Auto-scanned (streaming) |
| **Document** | .pdf .doc .ppt .xls | Skipped by default |
| **Text/Config** | .go .py .yaml .json .env .pem | Always scanned |

## License

See [LICENSE](LICENSE).
