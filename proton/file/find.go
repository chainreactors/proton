package file

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/common"
	"github.com/charlievieth/fastwalk"
	"github.com/gobwas/glob"
)

// getInputPaths parses the specified input paths and returns a compiled
// list of finished absolute paths to the files evaluating any allowlist, denylist,
// glob, file or folders, etc.
func (request *Request) getInputPaths(target string, callback func(string)) error {
	processed := make(map[string]struct{})

	// Template input includes a wildcard
	if strings.Contains(target, "*") && !request.NoRecursive {
		if err := request.findGlobPathMatches(target, processed, callback); err != nil {
			return fmt.Errorf("could not find glob matches, %s", err)
		}
		return nil
	}

	// Template input is either a file or a directory
	file, err := request.findFileMatches(target, processed, callback)
	if err != nil {
		return fmt.Errorf("could not find file, %s", err)
	}
	if file {
		return nil
	}
	if request.NoRecursive {
		return nil // we don't process dirs in no-recursive mode
	}
	// Recursively walk down the Templates directory and run all
	// the template file checks
	if err := request.findDirectoryMatches(target, processed, callback); err != nil {
		return fmt.Errorf("could not find directory matches, %s", err)
	}
	return nil
}

// splitGlobBase extracts the fixed directory prefix from a glob pattern.
// It walks backward from the first glob metacharacter to find the last
// path separator, splitting the pattern into a concrete base directory
// and a relative glob expression.
func splitGlobBase(pattern string) (baseDir, globPattern string) {
	metaIdx := -1
	for i, ch := range pattern {
		if ch == '*' || ch == '?' || ch == '[' || ch == '{' {
			metaIdx = i
			break
		}
	}
	if metaIdx < 0 {
		// No glob characters – treat the whole thing as a literal path.
		return filepath.Dir(pattern), filepath.Base(pattern)
	}
	// Find the last separator before the first metacharacter.
	prefix := pattern[:metaIdx]
	sepIdx := strings.LastIndexAny(prefix, `/\`)
	if sepIdx < 0 {
		return ".", pattern
	}
	return pattern[:sepIdx], pattern[sepIdx+1:]
}

// findGlobPathMatches returns the matched files from a glob path using
// fastwalk for parallel directory traversal and gobwas/glob for pattern
// matching (which also supports ** recursive wildcards).
func (request *Request) findGlobPathMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	baseDir, globPattern := splitGlobBase(absPath)

	compiled, err := glob.Compile(globPattern, '/')
	if err != nil {
		return fmt.Errorf("wildcard found, but unable to compile glob: %s", err)
	}

	var mu sync.Mutex
	walkErr := fastwalk.Walk(nil, baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, skip := defaultSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if _, deny := alwaysDenyExts[filepath.Ext(path)]; deny {
			return nil
		}
		rel, relErr := filepath.Rel(baseDir, path)
		if relErr != nil {
			return nil
		}
		// Use forward slashes for matching so the '/' separator works on all platforms.
		rel = filepath.ToSlash(rel)
		if !compiled.Match(rel) {
			return nil
		}
		if !request.validatePath(absPath, path, false) {
			return nil
		}
		mu.Lock()
		if _, ok := processed[path]; !ok {
			processed[path] = struct{}{}
			mu.Unlock()
			callback(path)
		} else {
			mu.Unlock()
		}
		return nil
	})
	return walkErr
}

// findFileMatches finds if a path is an absolute file. If the path
// is a file, it returns true otherwise false with no errors.
func (request *Request) findFileMatches(absPath string, processed map[string]struct{}, callback func(string)) (bool, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if _, ok := processed[absPath]; !ok {
		if !request.validatePath(absPath, absPath, false) {
			return false, nil
		}
		processed[absPath] = struct{}{}
		callback(absPath)
	}
	return true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (request *Request) findDirectoryMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	var mu sync.Mutex
	err := fastwalk.Walk(nil, absPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, skip := defaultSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if _, deny := alwaysDenyExts[filepath.Ext(path)]; deny {
			return nil
		}
		if !request.validatePath(absPath, path, false) {
			return nil
		}
		mu.Lock()
		if _, ok := processed[path]; !ok {
			processed[path] = struct{}{}
			mu.Unlock()
			callback(path)
		} else {
			mu.Unlock()
		}
		return nil
	})
	return err
}

// validatePath validates a file path for blacklist and whitelist options
func (request *Request) validatePath(absPath, item string, inArchive bool) bool {
	extension := filepath.Ext(item)
	// extension check
	if len(request.extensions) > 0 {
		if _, ok := request.extensions[extension]; ok {
			return true
		} else if !request.allExtensions {
			return false
		}
	}

	var (
		fileExists bool
		dataChunk  []byte
	)
	if !inArchive && request.MimeType {
		fileExists = common.IsExist(item)
		if fileExists {
			dataChunk, _ = readChunk(item)
			if len(request.mimeTypesChecks) > 0 && matchAnyMimeTypes(dataChunk, request.mimeTypesChecks) {
				return true
			}
		}
	}

	if matchingRule, ok := request.isInDenyList(absPath, item); ok {
		common.Logger().Warnf("Ignoring path %s due to denylist item %s\n", item, matchingRule)
		return false
	}

	// denied mime type checks
	if !inArchive && request.MimeType && fileExists {
		if len(request.denyMimeTypesChecks) > 0 && matchAnyMimeTypes(dataChunk, request.denyMimeTypesChecks) {
			return false
		}
	}

	// TextOnly mode: skip binary files via extension quick-path + content pre-check
	if request.useTextOnly && !inArchive {
		if !request.checkTextFile(item, extension, dataChunk) {
			return false
		}
	}

	return true
}

// checkTextFile determines whether a file is likely a text file.
// Level 1 (quick, zero I/O): extension in textExtensions whitelist.
// Level 2 (fallback): read first 1024 bytes and check for binary content.
// cachedChunk may be non-nil if MIME-type checking already read the first bytes.
func (request *Request) checkTextFile(item, extension string, cachedChunk []byte) bool {
	if extension == "" {
		return true
	}
	if _, ok := textExtensions[strings.ToLower(extension)]; ok {
		return true
	}
	if len(cachedChunk) > 0 {
		return isTextContent(cachedChunk)
	}
	chunk, err := readChunkPartial(item)
	if err != nil || len(chunk) == 0 {
		return true
	}
	return isTextContent(chunk)
}

func readChunkPartial(fileName string) ([]byte, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func (request *Request) isInDenyList(absPath, item string) (string, bool) {
	extension := filepath.Ext(item)
	// check for possible deny rules
	// - extension is in deny list
	if _, ok := request.denyList[extension]; ok {
		return extension, true
	}

	// - full path is in deny list
	if _, ok := request.denyList[item]; ok {
		return item, true
	}

	// file is in a forbidden subdirectory
	filename := filepath.Base(item)
	fullPathWithoutFilename := strings.TrimSuffix(item, filename)
	relativePathWithFilename := strings.TrimPrefix(item, absPath)
	relativePath := strings.TrimSuffix(relativePathWithFilename, filename)

	// - filename is in deny list
	if _, ok := request.denyList[filename]; ok {
		return filename, true
	}

	// - relative path is in deny list
	if _, ok := request.denyList[relativePath]; ok {
		return relativePath, true
	}

	// relative path + filename are in the forbidden list
	if _, ok := request.denyList[relativePathWithFilename]; ok {
		return relativePathWithFilename, true
	}

	// root path + relative path are in the forbidden list
	if _, ok := request.denyList[fullPathWithoutFilename]; ok {
		return fullPathWithoutFilename, true
	}

	// check any progressive combined part of the relative and absolute path with filename for matches within rules prefixes
	if pathTreeItem, ok := request.isAnyChunkInDenyList(relativePath, false); ok {
		return pathTreeItem, true
	}
	if pathTreeItem, ok := request.isAnyChunkInDenyList(item, true); ok {
		return pathTreeItem, true
	}

	return "", false
}

func readChunk(fileName string) ([]byte, error) {
	r, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer r.Close()

	var buff [1024]byte
	if _, err = io.ReadFull(r, buff[:]); err != nil {
		return nil, err
	}
	return buff[:], nil
}

func (request *Request) isAnyChunkInDenyList(path string, splitWithUtils bool) (string, bool) {
	var paths []string

	if splitWithUtils {
		// todo 目录的模糊匹配
		//pathInfo, _ := folderutil.NewPathInfo(path)
		//paths, _ = pathInfo.Paths()
	} else {
		pathTree := strings.Split(path, string(os.PathSeparator))
		for i := range pathTree {
			paths = append(paths, filepath.Join(pathTree[:i]...))
		}
	}
	for _, pathTreeItem := range paths {
		if _, ok := request.denyList[pathTreeItem]; ok {
			return pathTreeItem, true
		}
	}

	return "", false
}
