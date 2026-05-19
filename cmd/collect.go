package cmd

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainreactors/logs"
	ezip "github.com/yeka/zip"
)

type collectOpts struct {
	ZipPath  string
	Password string
	BaseDir  string
	KeepTree bool
	Findings []Finding
}

func collectFiles(opts collectOpts) error {
	// Deduplicate file paths, resolve archive internal paths
	pathSet := make(map[string]bool)
	for _, f := range opts.Findings {
		pathSet[resolveFilePath(f.FilePath)] = true
	}
	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}

	// Build zip name mapping
	nameMap := buildNameMap(paths, opts.BaseDir, opts.KeepTree)

	// Generate findings index JSON
	indexData, _ := json.MarshalIndent(opts.Findings, "", "  ")

	var fileCount int
	var err error
	if opts.Password != "" {
		fileCount, err = writeEncrypted(opts.ZipPath, opts.Password, paths, nameMap, indexData)
	} else {
		fileCount, err = writePlain(opts.ZipPath, paths, nameMap, indexData)
	}
	if err != nil {
		return err
	}
	logs.Log.Infof("Collected %d files to %s", fileCount, opts.ZipPath)
	return nil
}

func writePlain(zipPath string, paths []string, nameMap map[string]string, indexData []byte) (int, error) {
	f, err := os.Create(zipPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	w, _ := zw.Create("findings.json")
	w.Write(indexData)

	count := 0
	for _, path := range paths {
		zipName := nameMap[path]
		if err := addFileToZip(zw, path, zipName); err != nil {
			logs.Log.Warnf("collect: skip %s: %v", zipName, err)
			continue
		}
		count++
	}
	return count, nil
}

func writeEncrypted(zipPath, password string, paths []string, nameMap map[string]string, indexData []byte) (int, error) {
	f, err := os.Create(zipPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	zw := ezip.NewWriter(f)
	defer zw.Close()

	w, _ := zw.Encrypt("findings.json", password, ezip.AES256Encryption)
	w.Write(indexData)

	count := 0
	for _, path := range paths {
		zipName := nameMap[path]
		if err := addFileToEncryptedZip(zw, path, zipName, password); err != nil {
			logs.Log.Warnf("collect: skip %s: %v", zipName, err)
			continue
		}
		count++
	}
	return count, nil
}

func addFileToZip(zw *zip.Writer, filePath, zipName string) error {
	src, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer src.Close()
	w, err := zw.Create(zipName)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

func addFileToEncryptedZip(zw *ezip.Writer, filePath, zipName, password string) error {
	src, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer src.Close()
	w, err := zw.Encrypt(zipName, password, ezip.AES256Encryption)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

// resolveFilePath extracts the real filesystem path from a finding path.
// Archive internal paths like "/path/to/backup.tar:secrets.txt" resolve to "/path/to/backup.tar".
func resolveFilePath(path string) string {
	if idx := strings.Index(path, ":"); idx > 1 {
		return path[:idx]
	}
	return path
}

// buildNameMap creates the mapping from filesystem path to zip entry name.
// With keepTree=false (default), files are flattened to basename with dedup suffix.
// With keepTree=true, relative directory structure is preserved.
func buildNameMap(paths []string, baseDir string, keepTree bool) map[string]string {
	nameMap := make(map[string]string, len(paths))
	if keepTree {
		for _, p := range paths {
			if rel, err := filepath.Rel(baseDir, p); err == nil {
				nameMap[p] = filepath.ToSlash(rel)
			} else {
				nameMap[p] = filepath.Base(p)
			}
		}
		return nameMap
	}

	// Flat mode: basename with collision handling
	used := make(map[string]int)
	for _, p := range paths {
		base := filepath.Base(p)
		if n, ok := used[base]; ok {
			ext := filepath.Ext(base)
			stem := strings.TrimSuffix(base, ext)
			base = fmt.Sprintf("%s_%d%s", stem, n+1, ext)
			used[filepath.Base(p)] = n + 1
		} else {
			used[base] = 0
		}
		nameMap[p] = base
	}
	return nameMap
}
