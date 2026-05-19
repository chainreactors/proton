package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"io/fs"
	"strings"
	"time"
)

//go:embed templates.tar.gz
var embeddedTemplatesTarGz []byte

// embeddedFS implements fs.FS over the compressed templates archive.
type embeddedFS struct {
	files map[string][]byte
}

func newEmbeddedFS() (*embeddedFS, error) {
	gr, err := gzip.NewReader(bytes.NewReader(embeddedTemplatesTarGz))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	efs := &embeddedFS{files: make(map[string][]byte)}
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		efs.files[name] = data
	}
	return efs, nil
}

func (efs *embeddedFS) Open(name string) (fs.File, error) {
	data, ok := efs.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{name: name, data: data, reader: bytes.NewReader(data)}, nil
}

func (efs *embeddedFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	prefix := dir + "/"
	if dir == "." || dir == "" {
		prefix = ""
	}
	seen := make(map[string]bool)
	var entries []fs.DirEntry
	for name := range efs.files {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(name, prefix)
		if rest == "" {
			continue
		}
		if idx := strings.Index(rest, "/"); idx >= 0 {
			dirName := rest[:idx]
			if !seen[dirName] {
				seen[dirName] = true
				entries = append(entries, &memDirEntry{name: dirName, isDir: true})
			}
		} else {
			entries = append(entries, &memDirEntry{name: rest, isDir: false, size: int64(len(efs.files[name]))})
		}
	}
	return entries, nil
}

func (efs *embeddedFS) ReadFile(name string) ([]byte, error) {
	data, ok := efs.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	return data, nil
}

// ListCategories returns top-level directory names (template categories).
func (efs *embeddedFS) ListCategories() []string {
	cats := make(map[string]bool)
	for name := range efs.files {
		if idx := strings.Index(name, "/"); idx > 0 {
			cats[name[:idx]] = true
		}
	}
	var result []string
	for c := range cats {
		result = append(result, c)
	}
	return result
}

// FilesByCategory returns all file contents in a category directory.
func (efs *embeddedFS) FilesByCategory(cat string) map[string][]byte {
	prefix := cat + "/"
	result := make(map[string][]byte)
	for name, data := range efs.files {
		if strings.HasPrefix(name, prefix) {
			result[name] = data
		}
	}
	return result
}

type memFile struct {
	name   string
	data   []byte
	reader *bytes.Reader
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return &memFileInfo{name: f.name, size: int64(len(f.data))}, nil
}
func (f *memFile) Read(b []byte) (int, error) { return f.reader.Read(b) }
func (f *memFile) Close() error               { return nil }

type memFileInfo struct {
	name string
	size int64
}

func (fi *memFileInfo) Name() string      { return fi.name }
func (fi *memFileInfo) Size() int64       { return fi.size }
func (fi *memFileInfo) Mode() fs.FileMode { return 0444 }
func (fi *memFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *memFileInfo) IsDir() bool       { return false }
func (fi *memFileInfo) Sys() interface{}  { return nil }

type memDirEntry struct {
	name  string
	isDir bool
	size  int64
}

func (e *memDirEntry) Name() string               { return e.name }
func (e *memDirEntry) IsDir() bool                { return e.isDir }
func (e *memDirEntry) Type() fs.FileMode          { if e.isDir { return fs.ModeDir }; return 0 }
func (e *memDirEntry) Info() (fs.FileInfo, error)  { return &memFileInfo{name: e.name, size: e.size}, nil }
