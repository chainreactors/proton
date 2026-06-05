# proton

High-performance file content scanning engine for detecting leaked credentials, API keys, private keys, and other sensitive information in local filesystems.

proton provides two layers:

- **proton** (scanning engine) — `proton/file` package, three-layer scanning pipeline (prefilter → Aho-Corasick → RE2), can be imported as a Go library.
- **found** (CLI tool) — command-line scanner built on proton, with template management, output formatting, baseline diffing, auto-detection, and archive scanning.

## Architecture

proton's scanning pipeline processes each line through three progressively expensive layers, skipping work as early as possible:

1. **Prefilter** — `bytes.Contains` on raw `[]byte`, zero allocation (~4ns/line), skips lines with no possible match
2. **Aho-Corasick DFA** — multi-pattern index, selects the relevant regex subset per line
3. **RE2 regex** — only runs patterns identified by the previous layer (8.4x faster than Go stdlib regex)

File-level: single directory walk, multi-template evaluation, parallel file processing. Archives (tar/gz/zip/7z/rar) are scanned in streaming mode without disk extraction.

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

## Using as a Library

```go
import (
    "github.com/chainreactors/proton/proton/file"
    "github.com/chainreactors/neutron/protocols"
)

execOpts := &protocols.ExecuterOptions{
    Options: &protocols.Options{TextOnly: true},
}

inputs := []file.Rule{
    {ID: "my-rule", Name: "My Rule", Severity: "high", Requests: requests},
}

scanner := file.NewScanner(inputs, execOpts)
scanner.Scan("/path/to/target", func(f file.Finding) {
    fmt.Printf("[%s] %s: %s\n", f.Severity, f.TemplateID, f.FilePath)
})
```

## found CLI

### Quick Start

```bash
# Scan a directory with default templates (keys category)
found -i ~/projects

# Auto-detect OS and scan common sensitive directories
found --auto

# Auto-scan and package matched files
found --auto --collect findings.zip

# Scan with multiple template categories
found -i ~/projects -c keys,logs

# Only show high/critical severity findings
found -i ~/projects --severity high,critical

# Output as JSON and save to file
found -i ~/projects -j -s results.json

# Use custom template files
found -i ~/projects -t my-rules.yaml -t more-rules/

# Search with regex directly (like ripgrep)
found -i ~/projects -e "AKIA[0-9A-Z]{16}"

# Filter by template ID
found -i ~/projects --id private-key --id credential-exposure

# Exclude specific templates
found -i ~/projects --exclude-id noisy-rule --etags experimental

# List available templates
found --list

# Validate template files
found --validate -t my-rules/

# Download/update templates from a git repository
found --update-templates --template-url <repo>
```

### Usage

```
found [OPTIONS] -i <target>
```

#### Input Options

| Flag | Short | Description |
|------|-------|-------------|
| `--input` | `-i` | Target file or directory to scan |
| `--auto` | | Auto-detect OS and scan common sensitive directories |
| `--template` | `-t` | Template file or directory path (can specify multiple) |
| `--exclude-template` | | Template file or directory to exclude |
| `--category` | `-c` | Builtin template categories (default: `keys`) |
| `--id` | | Filter templates by ID (can specify multiple) |
| `--exclude-id` | | Exclude templates by ID |
| `--tags` | | Include only templates matching these tags |
| `--etags` | | Exclude templates matching these tags |
| `--expression` | `-e` | Regex pattern to search directly (can specify multiple) |
| `--ext` | | File extensions filter for `-e` mode (e.g. `.go,.py`) |
| `--ignore` | | Suppress reviewed findings via ignore rules (.foundignore.yaml) |

#### Output Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format: `text`, `json`, or `zombie` (default: `text`) |
| `--json` | `-j` | Shorthand for `-o json` |
| `--save` | `-s` | Save results to file |
| `--collect` | | Collect matched files into a zip archive |
| `--collect-tree` | | Preserve directory structure in collect zip |
| `--quiet` | `-q` | Only print findings, no banner or stats |
| `--no-color` | | Disable colored output |

#### Scan Options

| Flag | Description |
|------|-------------|
| `--bin` | Include binary/executable files in scan (default: text-only) |
| `--severity` | Filter by severity, comma-separated (`critical,high,medium,low,info`) |
| `--max-size` | Max file size to process (default: `1Gb`) |
| `--template-dir` | Template root directory (default: `/tmp/nuclei-templates/file`) |
| `--list` | List available templates and exit |
| `--validate` | Validate template files and exit |
| `--template-display` | Display template content by ID or file path |
| `--baseline` | Load baseline file to suppress known findings |
| `--findings` | Save findings in baseline format |
| `--fail-on` | Exit with code 1 if findings match severity (e.g. `high,critical`) |

#### Template Management

| Flag | Description |
|------|-------------|
| `--update-templates` | Download or update templates from a git repository |
| `--template-url` | Custom template repository URL (saved to config) |
| `--update-template-dir` | Custom directory for template installation |

### Output Example

#### Text Format

```
[HIG] private-key (Private Key Detect)
       File: src/config/server.pem
       Match: BEGIN RSA PRIVATE KEY

[HIG] credential-exposure (Credential Exposure)
       File: deploy/docker-compose.yml
       Match: DB_PASSWORD=s3cret_value
```

#### JSON Format

```json
{"template_id":"private-key","template_name":"Private Key Detect","severity":"high","file":"src/config/server.pem","extracts":["BEGIN RSA PRIVATE KEY"]}
```

## Template Format

Templates use the Nuclei file protocol YAML format:

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

### Template Fields

| Field | Description |
|-------|-------------|
| `id` | Unique template identifier |
| `info.name` | Human-readable template name |
| `info.severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `info.tags` | Comma-separated tags for filtering |
| `file[].extensions` | File extensions to scan (`all` for everything) |
| `file[].denylist` | Extensions or paths to exclude |
| `file[].max-size` | Max file size for this template |
| `file[].matchers` | Matching rules: `word`, `regex`, `binary`, `dsl` |
| `file[].extractors` | Extraction rules: `regex` (with capture groups), `kval` |
| `file[].matchers-condition` | `or` (default) or `and` |

## Benchmark

Intel Core Ultra 9 285H, all 156 built-in templates (863 regex patterns), real source files from a monorepo. Naive = Go stdlib regex, full-body scan per pattern, sequential, no prefilter.

| Data | Files | proton | naive | Speedup |
|------|-------|--------|-------|---------|
| 1 KB | 1 | 151 µs | 4 ms | **28x** |
| 1 MB | 137 | 362 µs | 18.4 s | **50,000x** |
| 1 GB | 162,258 | 34 ms | ~5h (projected) | **540,000x** |


### File Filtering

| Category | Examples | Behavior |
|----------|---------|----------|
| **Media/Font** | .png .jpg .mp4 .mp3 .ttf .woff | Always skipped at walk level |
| **Executable** | .exe .dll .so .class .pyc | Skipped by default; `--bin` to include |
| **Archive** | .tar .gz .zip .7z .rar | Auto-scanned inside (streaming, no disk extraction) |
| **Document** | .pdf .doc .ppt .xls | Skipped by default |
| **Text/Config** | .go .py .yaml .json .env .pem | Always scanned |

### Directory Pruning

Automatically skipped: `node_modules` `bower_components` `__pycache__` `.tox` `.eggs` `.svn` `.hg` `.idea` `.vscode` `.gradle`

**Not skipped:** `.git` (history may contain leaked credentials), `vendor`, `dist`, `build`

## License

See [LICENSE](LICENSE).
