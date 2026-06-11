package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

const version = "v0.2.0"

var (
	scanners   = make(map[int]*file.Scanner)
	scannersMu sync.RWMutex
	nextHandle int64
)

//export ProtonVersion
func ProtonVersion() *C.char {
	return C.CString(version)
}

//export ProtonNewScanner
func ProtonNewScanner(path *C.char) C.int {
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

	var findings []file.Finding
	for _, group := range s.Groups {
		for _, f := range s.ScanData(goData, goPath, group) {
			findings = append(findings, f)
		}
	}

	result, _ := json.Marshal(findings)
	return C.CString(string(result))
}

//export ProtonScanBlock
func ProtonScanBlock(handle C.int, data unsafe.Pointer, dataLen C.int, label *C.char) *C.char {
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
	goLabel := ""
	if label != nil {
		goLabel = C.GoString(label)
	}

	var findings []file.Finding
	for _, group := range s.Groups {
		for _, f := range s.ScanBlock(goData, goLabel, group) {
			findings = append(findings, f)
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
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
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

func main() {}
