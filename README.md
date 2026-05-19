# found

High-performance file content scanner for detecting leaked credentials, API keys, private keys, and other sensitive information in local filesystems.

## Features

- **Template-based detection** — uses YAML templates (compatible with Nuclei file protocol) to define regex/word matching rules
- **High throughput** — single-walk multi-template scanning with parallel file processing
- **Archive scanning** — automatically scans inside tar/tar.gz/zip/7z/rar without manual extraction
- **Smart filtering** — skips media files, font files, and known-useless directories (node_modules, \_\_pycache\_\_) at walk level
- **Multiple output formats** — text (human-readable) and JSON (machine-parseable)

## Installation

```bash
go install github.com/chainreactors/found@latest
```

Or build from source:

```bash
git clone https://github.com/chainreactors/found
cd found
go build -o found .
```

## Quick Start

```bash
# Scan a directory with default templates (keys category)
found -i ~/projects

# Scan with multiple template categories
found -i ~/projects -c keys,logs

# Only show high/critical severity findings
found -i ~/projects --severity high,critical

# Output as JSON and save to file
found -i ~/projects -o json -s results.json

# Use custom template files
found -i ~/projects -t my-rules.yaml -t more-rules/

# Filter by template ID
found -i ~/projects --id private-key --id credential-exposure

# Exclude specific templates
found -i ~/projects --exclude-id noisy-rule --etags experimental

# List available templates
found --list
```

## Usage

```
found [OPTIONS] -i <target>
```

### Input Options

| Flag | Short | Description |
|------|-------|-------------|
| `--input` | `-i` | Target file or directory to scan |
| `--template` | `-t` | Template file or directory path (can specify multiple) |
| `--exclude-template` | | Template file or directory to exclude |
| `--category` | `-c` | Builtin template categories (default: `keys`) |
| `--id` | | Filter templates by ID (can specify multiple) |
| `--exclude-id` | | Exclude templates by ID |
| `--tags` | | Include only templates matching these tags |
| `--etags` | | Exclude templates matching these tags |

### Output Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format: `text` or `json` (default: `text`) |
| `--save` | `-s` | Save results to file |
| `--quiet` | `-q` | Only print findings, no banner or summary |

### Scan Options

| Flag | Description |
|------|-------------|
| `--bin` | Include binary/executable files in scan (default: text-only) |
| `--severity` | Filter by severity, comma-separated (`critical,high,medium,low,info`) |
| `--max-size` | Max file size to process (default: `1Gb`) |
| `--template-dir` | Template root directory (default: `/tmp/nuclei-templates/file`) |
| `--list` | List available templates and exit |

## Output Example

### Text Format

```
[HIG] private-key (Private Key Detect)
       File: src/config/server.pem
       Match: BEGIN RSA PRIVATE KEY

[HIG] credential-exposure (Credential Exposure)
       File: deploy/docker-compose.yml
       Match: DB_PASSWORD=s3cret_value
```

### JSON Format

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

## Architecture

```
found (CLI)
  └── proton (scanning engine)
        ├── Scanner.Scan()         — single directory walk, multi-template evaluation
        ├── processFile()          — regular files via mmap/ReadFile
        ├── processArchive()       — tar/gz/zip (stdlib), 7z/rar (mholt/archives)
        └── scanData()             — line scanning pipeline
              ├── Layer 1: prefilter    — bytes.Contains on []byte, SIMD-accelerated, 0 alloc
              ├── Layer 2: patternIndex — Aho-Corasick DFA, selects relevant regex subset
              └── Layer 3: RE2 regex    — only runs patterns identified by Layer 2
```

### Performance

Benchmarks on 100 files x 10KB, 5 templates (Intel Ultra 9 285H):

| Scenario | Throughput |
|----------|-----------|
| 1000 small files (1KB) | ~100 files/ms |
| 100 large files (100KB) | ~8 files/ms |
| 50 templates, high match rate | 3x faster than naive approach |

### File Filtering

| Category | Examples | Behavior |
|----------|---------|----------|
| **Media/Font** | .png .jpg .mp4 .mp3 .ttf .woff | Always skipped at walk level |
| **Executable** | .exe .dll .so .class .pyc | Skipped by default; `--bin` to include |
| **Archive** | .tar .gz .zip .7z .rar | Auto-scanned inside (streaming, no disk extraction) |
| **Document** | .pdf .doc .ppt .xls | Skipped by default |
| **Text/Config** | .go .py .yaml .json .env .pem | Always scanned |

### Directory Pruning

Automatically skipped (zero audit value):

`node_modules` `bower_components` `__pycache__` `.tox` `.eggs` `.svn` `.hg` `.idea` `.vscode` `.gradle`

**Not skipped:** `.git` (history may contain leaked credentials), `vendor`, `dist`, `build`

## License

See [LICENSE](LICENSE).
