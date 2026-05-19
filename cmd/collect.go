package cmd

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainreactors/logs"
	ezip "github.com/yeka/zip"
)

func collectFiles(zipPath, password, baseDir string, paths []string) error {
	if password != "" {
		return collectEncrypted(zipPath, password, baseDir, paths)
	}
	return collectPlain(zipPath, baseDir, paths)
}

func collectPlain(zipPath, baseDir string, paths []string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for _, path := range paths {
		relPath := toRelPath(path, baseDir)
		if err := addFileToZip(zw, path, relPath); err != nil {
			logs.Log.Warnf("collect: skip %s: %v", relPath, err)
		}
	}
	return nil
}

func collectEncrypted(zipPath, password, baseDir string, paths []string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := ezip.NewWriter(f)
	defer zw.Close()

	for _, path := range paths {
		relPath := toRelPath(path, baseDir)
		if err := addFileToEncryptedZip(zw, path, relPath, password); err != nil {
			logs.Log.Warnf("collect: skip %s: %v", relPath, err)
		}
	}
	return nil
}

func addFileToZip(zw *zip.Writer, filePath, relPath string) error {
	src, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer src.Close()

	w, err := zw.Create(relPath)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

func addFileToEncryptedZip(zw *ezip.Writer, filePath, relPath, password string) error {
	src, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer src.Close()

	w, err := zw.Encrypt(relPath, password, ezip.AES256Encryption)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

// toRelPath converts an absolute file path to a relative path for the zip.
// For archive internal files (path contains ":"), extracts the archive path.
func toRelPath(path, baseDir string) string {
	// archive internal: /path/to/backup.tar:secrets.txt → collect the tar itself
	if idx := strings.Index(path, ":"); idx > 0 {
		// Check it's not a Windows drive letter (C:\...)
		if idx > 1 {
			path = path[:idx]
		}
	}
	if rel, err := filepath.Rel(baseDir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Base(path))
}
