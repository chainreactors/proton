package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const version = "v0.1.1"

var (
	scanners   = make(map[int]*file.Scanner)
	scannersMu sync.RWMutex
	nextHandle int64
)

func init() {
	loadFiltersFromEmbedded()
}

//export ProtonVersion
func ProtonVersion() *C.char {
	return C.CString(version)
}

//export ProtonNewScanner
func ProtonNewScanner(category *C.char) C.int {
	cat := "keys"
	if category != nil {
		cat = C.GoString(category)
	}

	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{},
	}

	tmpls := loadEmbeddedTemplates(cat, execOpts)
	if len(tmpls) == 0 {
		return 0
	}

	var inputs []file.Rule
	for _, tmpl := range tmpls {
		inputs = append(inputs, file.Rule{
			ID:       tmpl.Id,
			Name:     tmpl.Info.Name,
			Severity: tmpl.Info.Severity,
			Requests: tmpl.RequestsFile,
		})
	}

	scanner := file.NewScanner(inputs, execOpts)
	handle := int(atomic.AddInt64(&nextHandle, 1))
	scannersMu.Lock()
	scanners[handle] = scanner
	scannersMu.Unlock()
	return C.int(handle)
}

//export ProtonNewScannerFromPath
func ProtonNewScannerFromPath(path *C.char) C.int {
	if path == nil {
		return 0
	}
	goPath := C.GoString(path)

	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{},
	}

	tmpls, err := loadFromPath(goPath, execOpts)
	if err != nil || len(tmpls) == 0 {
		return 0
	}

	var inputs []file.Rule
	for _, tmpl := range tmpls {
		inputs = append(inputs, file.Rule{
			ID:       tmpl.Id,
			Name:     tmpl.Info.Name,
			Severity: tmpl.Info.Severity,
			Requests: tmpl.RequestsFile,
		})
	}

	scanner := file.NewScanner(inputs, execOpts)
	handle := int(atomic.AddInt64(&nextHandle, 1))
	scannersMu.Lock()
	scanners[handle] = scanner
	scannersMu.Unlock()
	return C.int(handle)
}

type findingJSON struct {
	TemplateID   string                       `json:"template-id"`
	TemplateName string                       `json:"template-name"`
	Severity     string                       `json:"severity"`
	FilePath     string                       `json:"file"`
	Matches      map[string][]file.MatchEvent `json:"matches,omitempty"`
	Extracts     []file.MatchEvent            `json:"extracts,omitempty"`
}

//export ProtonScanDir
func ProtonScanDir(handle C.int, target *C.char) *C.char {
	if target == nil {
		return C.CString("[]")
	}
	scannersMu.RLock()
	s, ok := scanners[int(handle)]
	scannersMu.RUnlock()
	if !ok {
		return C.CString("[]")
	}

	goTarget := C.GoString(target)
	var mu sync.Mutex
	var findings []findingJSON

	s.Scan(goTarget, func(f file.Finding) {
		fj := findingJSON{
			TemplateID:   f.TemplateID,
			TemplateName: f.TemplateName,
			Severity:     f.Severity,
			FilePath:     f.FilePath,
			Matches:      f.Matches,
			Extracts:     f.Extracts,
		}
		mu.Lock()
		findings = append(findings, fj)
		mu.Unlock()
	})

	data, _ := json.Marshal(findings)
	return C.CString(string(data))
}

//export ProtonScanData
func ProtonScanData(handle C.int, data unsafe.Pointer, dataLen C.int, filePath *C.char) *C.char {
	if data == nil || dataLen <= 0 {
		return C.CString("[]")
	}
	scannersMu.RLock()
	s, ok := scanners[int(handle)]
	scannersMu.RUnlock()
	if !ok {
		return C.CString("[]")
	}

	goData := C.GoBytes(data, dataLen)
	goPath := ""
	if filePath != nil {
		goPath = C.GoString(filePath)
	}

	var findings []findingJSON
	for _, group := range s.Groups {
		results := s.ScanData(goData, goPath, group)
		for _, f := range results {
			findings = append(findings, findingJSON{
				TemplateID:   f.TemplateID,
				TemplateName: f.TemplateName,
				Severity:     f.Severity,
				FilePath:     f.FilePath,
				Matches:      f.Matches,
				Extracts:     f.Extracts,
			})
		}
	}

	result, _ := json.Marshal(findings)
	return C.CString(string(result))
}

//export ProtonFreeScanner
func ProtonFreeScanner(handle C.int) {
	scannersMu.Lock()
	delete(scanners, int(handle))
	scannersMu.Unlock()
}

//export ProtonFreeString
func ProtonFreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func loadEmbeddedTemplates(category string, execOpts *protocols.ExecuterOptions) []*template.Template {
	configs := embeddedTemplateConfigs(category)
	var tmpls []*template.Template
	for _, config := range configs {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if err := yaml.Unmarshal(data, &pocs); err != nil {
			continue
		}
		for _, poc := range pocs {
			bs, err := yaml.Marshal(poc)
			if err != nil {
				continue
			}
			tmpl, err := parseTemplate(bs, execOpts)
			if err != nil {
				continue
			}
			tmpls = append(tmpls, tmpl)
		}
	}
	return tmpls
}

func embeddedTemplateConfigs(category string) []string {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		category = "keys"
	}
	switch category {
	case "all":
		return []string{"found_keys", "found_spray"}
	case "key", "keys", "found/keys", "found_keys":
		return []string{"found_keys"}
	case "spray", "found/spray", "found_spray":
		return []string{"found_spray"}
	default:
		return []string{"found_" + category}
	}
}

func parseTemplate(data []byte, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	var tmpl template.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}
	if len(tmpl.RequestsFile) == 0 {
		return nil, nil
	}
	if err := tmpl.Compile(execOpts); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

func loadFromPath(path string, execOpts *protocols.ExecuterOptions) ([]*template.Template, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		tmpl, err := parseTemplate(data, execOpts)
		if err != nil {
			return nil, err
		}
		if tmpl == nil {
			return nil, nil
		}
		return []*template.Template{tmpl}, nil
	}

	var tmpls []*template.Template
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		tmpl, err := parseTemplate(data, execOpts)
		if err != nil || tmpl == nil {
			return nil
		}
		tmpls = append(tmpls, tmpl)
		return nil
	})
	return tmpls, nil
}

func loadFiltersFromEmbedded() {
	cfg := file.FilterConfig{}
	if extData := pkg.LoadConfig("found_filter_ext"); len(extData) > 0 {
		var extGroups map[string][]string
		if yaml.Unmarshal(extData, &extGroups) == nil {
			cfg.AlwaysDenyExts = toExtSet(extGroups["always"])
			cfg.ExecDenyExts = toExtSet(extGroups["executable"])
			cfg.ArchiveDenyExts = toExtSet(extGroups["archive"])
			cfg.DocDenyExts = toExtSet(extGroups["document"])
			cfg.MiscDenyExts = toExtSet(extGroups["misc"])
		}
	}
	if dirData := pkg.LoadConfig("found_filter_dir"); len(dirData) > 0 {
		var dirGroups map[string][]string
		if yaml.Unmarshal(dirData, &dirGroups) == nil {
			cfg.SkipDirs = toExtSet(dirGroups["skip"])
		}
	}
	file.SetFilters(cfg)
}

func toExtSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

func main() {}
