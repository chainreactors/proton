package file

import (
	"fmt"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
)

var (
	defaultMaxReadSize, _ = common.FromHumanSize("1Gb")
	chunkSize, _          = common.FromHumanSize("100Mb")
)

// Request contains a File matching mechanism for local disk operations.
type Request struct {
	// Operators for the current request go here.
	operators.Operators `json:",inline" yaml:",inline"`
	// description: |
	//   Extensions is the list of extensions or mime types to perform matching on.
	// examples:
	//   - value: '[]string{".txt", ".go", ".json"}'
	Extensions []string `json:"extensions,omitempty" yaml:"extensions,omitempty" jsonschema:"title=extensions to match,description=List of extensions to perform matching on"`
	// description: |
	//   DenyList is the list of file, directories, mime types or extensions to deny during matching.
	//
	//   By default, it contains some non-interesting extensions that are hardcoded
	//   in nuclei.
	// examples:
	//   - value: '[]string{".avi", ".mov", ".mp3"}'
	DenyList []string `yaml:"json,omitempty" yaml:"denylist,omitempty" jsonschema:"title=denylist, directories and extensions to deny match,description=List of files, directories and extensions to deny during matching"`

	// ID is the optional id of the request
	ID string `json:"id,omitempty" yaml:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID for the request"`

	// description: |
	//   MaxSize is the maximum size of the file to run request on.
	//
	//   By default, nuclei will process 1 GB of content and not go more than that.
	//   It can be set to much lower or higher depending on use.
	//   If set to "no" then all content will be processed
	// examples:
	//   - value: "\"5Mb\""
	MaxSize string `json:"max-size,omitempty"  yaml:"max-size,omitempty" jsonschema:"title=max size data to run request on,description=Maximum size of the file to run request on"`
	maxSize int64

	// description: |
	//   elaborates archives
	Archive bool

	// description: |
	//   enables mime types check
	MimeType bool

	// ScanAll forces scanning all file types even when TextOnly mode is enabled.
	ScanAll bool `json:"scan-all,omitempty" yaml:"scan-all,omitempty"`

	CompiledOperators *operators.Operators `json:"-" yaml:"-"`

	prefilter          *linePrefilter
	staticWordMatchers map[*operators.Matcher]bool

	// cache any variables that may be needed for operation.
	options             *protocols.ExecuterOptions
	mimeTypesChecks     []string
	extensions          map[string]struct{}
	denyList            map[string]struct{}
	denyMimeTypesChecks []string

	// description: |
	//   NoRecursive specifies whether to not do recursive checks if folders are provided.
	NoRecursive bool `json:"no-recursive,omitempty" yaml:"no-recursive,omitempty" jsonschema:"title=do not perform recursion,description=Specifies whether to not do recursive checks if folders are provided"`

	allExtensions bool
	useTextOnly   bool
}

// textExtensions is a quick-path whitelist of known text file extensions.
// Files with these extensions skip the 1024-byte binary pre-check.
var textExtensions = map[string]struct{}{
	".env": {}, ".ini": {}, ".conf": {}, ".cfg": {}, ".config": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".json": {}, ".xml": {},
	".properties": {}, ".plist": {}, ".htaccess": {},
	".go": {}, ".py": {}, ".js": {}, ".ts": {}, ".java": {}, ".rb": {},
	".php": {}, ".pl": {}, ".sh": {}, ".bash": {}, ".zsh": {},
	".rs": {}, ".c": {}, ".cpp": {}, ".h": {}, ".cs": {}, ".swift": {},
	".kt": {}, ".scala": {}, ".lua": {}, ".groovy": {}, ".r": {},
	".html": {}, ".htm": {}, ".jsx": {}, ".tsx": {}, ".vue": {},
	".css": {}, ".scss": {}, ".less": {},
	".sql": {}, ".csv": {}, ".md": {}, ".txt": {}, ".log": {},
	".rst": {}, ".tex": {},
	".tf": {}, ".hcl": {},
	".pem": {}, ".key": {}, ".crt": {}, ".cer": {}, ".pub": {},
	".asc": {}, ".der": {},
	".npmrc": {}, ".pypirc": {}, ".gemrc": {},
	".pyi": {}, ".pyx": {}, ".pxd": {},
	".mod": {}, ".sum": {}, ".work": {},
	".proto": {}, ".thrift": {}, ".avdl": {},
	".graphql": {}, ".gql": {},
	".svelte": {}, ".astro": {},
	".zig": {}, ".nim": {}, ".v": {}, ".d": {},
	".cmake": {}, ".mk": {}, ".makefile": {},
	".dockerfile": {}, ".containerfile": {},
	".tfvars": {},
	".gradle": {}, ".sbt": {}, ".maven": {},
	".bat": {}, ".cmd": {}, ".ps1": {}, ".psm1": {},
	".fish": {}, ".elvish": {},
	".lock": {}, ".golden": {}, ".snap": {},
	".wat": {}, ".wast": {},
	".s": {}, ".asm": {},
}

// isTextContent checks whether data looks like text content by examining
// for null bytes and the ratio of non-printable control characters.
func isTextContent(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	nonText := 0
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D {
			nonText++
		}
	}
	return float64(nonText)/float64(len(data)) < 0.30
}

// FilterConfig allows callers to override the default extension and directory filters.
type FilterConfig struct {
	AlwaysDenyExts map[string]struct{}
	ExecDenyExts   map[string]struct{}
	ArchiveDenyExts map[string]struct{}
	DocDenyExts    map[string]struct{}
	MiscDenyExts   map[string]struct{}
	SkipDirs       map[string]struct{}
}

// SetFilters replaces the package-level filter maps with values from cfg.
// Only non-nil fields are applied.
func SetFilters(cfg FilterConfig) {
	if cfg.AlwaysDenyExts != nil {
		alwaysDenyExts = cfg.AlwaysDenyExts
	}
	if cfg.ExecDenyExts != nil {
		execDenyExts = cfg.ExecDenyExts
	}
	if cfg.ArchiveDenyExts != nil {
		archiveDenyExts = cfg.ArchiveDenyExts
	}
	if cfg.DocDenyExts != nil {
		docDenyExts = cfg.DocDenyExts
	}
	if cfg.MiscDenyExts != nil {
		miscDenyExts = cfg.MiscDenyExts
	}
	if cfg.SkipDirs != nil {
		defaultSkipDirs = cfg.SkipDirs
	}
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":       "ID of the template executed",
	"template-info":     "Info Block of the template executed",
	"template-path":     "Path of the template executed",
	"matched":           "Matched is the input which was matched upon",
	"path":              "Path is the path of file on local filesystem",
	"type":              "Type is the type of request made",
	"raw,body,all,data": "Raw contains the raw file contents",
}

// alwaysDenyExts are pure media/font files with 0% chance of containing credentials.
// Filtered at walk level before any path collection.
var alwaysDenyExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".gifv": {},
	".bmp": {}, ".ico": {}, ".tif": {}, ".tiff": {}, ".psd": {},
	".xcf": {}, ".svg": {}, ".webp": {},
	".mp4": {}, ".avi": {}, ".mkv": {}, ".mov": {}, ".flv": {},
	".wmv": {}, ".webm": {}, ".mpeg": {}, ".mpg": {}, ".3gp": {},
	".3g2": {}, ".h264": {}, ".m4v": {}, ".ogv": {}, ".ogm": {},
	".vob": {}, ".swf": {},
	".mp3": {}, ".wav": {}, ".ogg": {}, ".m4a": {}, ".rm": {},
	".ttf": {}, ".otf": {}, ".woff": {}, ".woff2": {}, ".eot": {},
}

// execDenyExts are executables/libraries. May contain embedded credentials.
// Skipped by default; included when ScanAll is set on the request.
var execDenyExts = map[string]struct{}{
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".sys": {},
	".drv": {}, ".msi": {}, ".deb": {}, ".rpm": {}, ".pkg": {},
	".class": {}, ".pyc": {}, ".o": {}, ".a": {},
}

// archiveDenyExts are compressed archives. Skipped by default;
// included when the Archive flag is set on the request.
var archiveDenyExts = map[string]struct{}{
	".zip": {}, ".tar": {}, ".gz": {}, ".7z": {}, ".rar": {},
	".apk": {}, ".jar": {}, ".iso": {},
}

// docDenyExts are binary document formats.
var docDenyExts = map[string]struct{}{
	".pdf": {}, ".doc": {}, ".ppt": {}, ".xls": {}, ".xlsx": {},
}

// miscDenyExts are other files with no security audit value.
var miscDenyExts = map[string]struct{}{
	".lock": {}, ".map": {}, ".axd": {}, ".csv": {},
}

// defaultSkipDirs are directories with 0% audit value — skipped at walk level.
// .git is NOT included: history may contain leaked credentials.
var defaultSkipDirs = map[string]struct{}{
	"node_modules":     {},
	"bower_components": {},
	"__pycache__":      {},
	".tox":             {},
	".eggs":            {},
	".svn":             {},
	".hg":              {},
	".idea":            {},
	".vscode":          {},
	".gradle":          {},
	".cache":           {},
	".local":           {},
	".npm":             {},
	".yarn":            {},
	".cargo":           {},
	".rustup":          {},
	".goenv":           {},
	".rbenv":           {},
	".pyenv":           {},
	".nvm":             {},
	"site-packages":    {},
}

// defaultDenylist is the legacy flat list for backward compatibility.
// New code should use the categorized maps above.
var defaultDenylist []string

// defaultArchiveDenyList is kept for backward compatibility with existing callers.
var defaultArchiveDenyList []string

func init() {
	for ext := range alwaysDenyExts {
		defaultDenylist = append(defaultDenylist, ext)
	}
	for ext := range execDenyExts {
		defaultDenylist = append(defaultDenylist, ext)
	}
	for ext := range docDenyExts {
		defaultDenylist = append(defaultDenylist, ext)
	}
	for ext := range miscDenyExts {
		defaultDenylist = append(defaultDenylist, ext)
	}
	for ext := range archiveDenyExts {
		defaultArchiveDenyList = append(defaultArchiveDenyList, ext)
	}
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if err := compiled.Compile(); err != nil {
			return fmt.Errorf("could not compile operators, %s", err)
		}
		request.CompiledOperators = compiled
		request.prefilter = buildPrefilter(request.CompiledOperators)
	}

	// Identify static word matchers (no template expressions) so that
	// Match() can use the fast matchWordsStatic path.
	request.staticWordMatchers = make(map[*operators.Matcher]bool)
	if request.CompiledOperators != nil {
		for _, m := range request.CompiledOperators.Matchers {
			if m.GetType() == operators.WordsMatcher {
				isStatic := true
				for _, w := range m.Words {
					if strings.Contains(w, "{{") {
						isStatic = false
						break
					}
				}
				request.staticWordMatchers[m] = isStatic
			}
		}
	}

	// By default, use default max size if not defined
	switch {
	case request.MaxSize != "":
		maxSize, err := common.FromHumanSize(request.MaxSize)
		if err != nil {
			return fmt.Errorf("could not compile operators, %s", err)
		}
		request.maxSize = maxSize
	case request.MaxSize == "no":
		request.maxSize = -1
	default:
		request.maxSize = defaultMaxReadSize
	}

	request.options = options

	request.extensions = make(map[string]struct{})
	request.denyList = make(map[string]struct{})

	for _, extension := range request.Extensions {
		switch {
		case extension == "all":
			request.allExtensions = true
		case request.MimeType && filetype.IsMIMESupported(extension):
			continue
		default:
			if !strings.HasPrefix(extension, ".") {
				extension = "." + extension
			}
			request.extensions[extension] = struct{}{}
		}
	}
	request.mimeTypesChecks = extractMimeTypes(request.Extensions)

	// Determine TextOnly mode: enabled when the engine option is set,
	// extensions is "all", and the template doesn't opt out via scan-all.
	if options != nil && options.Options != nil && options.Options.TextOnly &&
		request.allExtensions && !request.ScanAll {
		request.useTextOnly = true
	}

	// process default denylist (extensions)
	var denyList []string
	if !request.Archive {
		denyList = append(defaultDenylist, defaultArchiveDenyList...)
	} else {
		denyList = defaultDenylist
	}
	for _, excludeItem := range denyList {
		if !strings.HasPrefix(excludeItem, ".") {
			excludeItem = "." + excludeItem
		}
		request.denyList[excludeItem] = struct{}{}
	}
	for _, excludeItem := range request.DenyList {
		request.denyList[excludeItem] = struct{}{}
		request.denyList[filepath.Clean(excludeItem)] = struct{}{}
	}
	request.denyMimeTypesChecks = extractMimeTypes(request.DenyList)
	return nil
}

func matchAnyMimeTypes(data []byte, mimeTypes []string) bool {
	for _, mimeType := range mimeTypes {
		if filetype.Is(data, mimeType) {
			return true
		}
	}
	return false
}

func extractMimeTypes(m []string) []string {
	var mimeTypes []string
	for _, mm := range m {
		if !filetype.IsMIMESupported(mm) {
			continue
		}
		mimeTypes = append(mimeTypes, mm)
	}
	return mimeTypes
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 0
}
