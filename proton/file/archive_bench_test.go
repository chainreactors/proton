//go:build go1.18
// +build go1.18

package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	oldarchiver "github.com/mholt/archiver"
)

const archiveBenchFileCount = 100
const archiveBenchFileSize = 10 * 1024

func generateFileContent(idx, size int) []byte {
	var sb strings.Builder
	sb.Grow(size + 256)
	filler := fmt.Sprintf("package main // file %d\nfunc init() {}\n", idx)
	secret := fmt.Sprintf("password = secret_value_%d\n", idx)
	lineNum := 0
	for sb.Len() < size {
		if lineNum == 5 {
			sb.WriteString(secret)
		} else {
			sb.WriteString(filler)
		}
		lineNum++
	}
	return []byte(sb.String()[:size])
}

func createBenchTar(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.tar")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("dir/file_%04d.txt", i),
			Size: int64(len(content)),
			Mode: 0644,
		})
		tw.Write(content)
	}
	tw.Close()
	f.Close()
	return path
}

func createBenchTarGz(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("dir/file_%04d.txt", i),
			Size: int64(len(content)),
			Mode: 0644,
		})
		tw.Write(content)
	}
	tw.Close()
	gw.Close()
	f.Close()
	return path
}

func createBenchZip(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.zip")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := 0; i < archiveBenchFileCount; i++ {
		content := generateFileContent(i, archiveBenchFileSize)
		w, _ := zw.Create(fmt.Sprintf("dir/file_%04d.txt", i))
		w.Write(content)
	}
	zw.Close()
	f.Close()
	return path
}

// --- stdlib approach ---

func readAllStdlibTar(path string) (int, int) {
	f, _ := os.Open(path)
	defer f.Close()
	tr := tar.NewReader(f)
	files, totalBytes := 0, 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, _ := io.ReadAll(tr)
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

func readAllStdlibTarGz(path string) (int, int) {
	f, _ := os.Open(path)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	defer gr.Close()
	tr := tar.NewReader(gr)
	files, totalBytes := 0, 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, _ := io.ReadAll(tr)
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

func readAllStdlibZip(path string) (int, int) {
	r, _ := zip.OpenReader(path)
	defer r.Close()
	files, totalBytes := 0, 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		totalBytes += len(data)
		if bytes.Contains(data, []byte("password")) {
			files++
		}
	}
	return files, totalBytes
}

// --- mholt/archiver v3 approach ---

func readAllArchiverV3(path string) (int, int) {
	archiveReader, _ := oldarchiver.ByExtension(path)
	if archiveReader == nil {
		return 0, 0
	}
	files, totalBytes := 0, 0
	switch inst := archiveReader.(type) {
	case oldarchiver.Walker:
		inst.Walk(path, func(file oldarchiver.File) error {
			if file.IsDir() {
				return nil
			}
			data, _ := io.ReadAll(file.ReadCloser)
			file.Close()
			totalBytes += len(data)
			if bytes.Contains(data, []byte("password")) {
				files++
			}
			return nil
		})
	case oldarchiver.Decompressor:
		f, err := os.Open(path)
		if err != nil {
			return 0, 0
		}
		defer f.Close()
		tmpFile, _ := os.CreateTemp("", "bench-decomp-*")
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()
		inst.Decompress(f, tmpFile)
		tmpFile.Seek(0, 0)
		data, _ := io.ReadAll(tmpFile)
		totalBytes = len(data)
		if bytes.Contains(data, []byte("password")) {
			files = 1
		}
	}
	return files, totalBytes
}

// === Benchmarks ===

func BenchmarkArchive_Tar(b *testing.B) {
	tarPath := createBenchTar(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibTar(tarPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(tarPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}

func BenchmarkArchive_TarGz(b *testing.B) {
	tgzPath := createBenchTarGz(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibTarGz(tgzPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(tgzPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}

func BenchmarkArchive_Zip(b *testing.B) {
	zipPath := createBenchZip(b)

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllStdlibZip(zipPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})

	b.Run("archiver_v3", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			files, bytes := readAllArchiverV3(zipPath)
			if files != archiveBenchFileCount || bytes == 0 {
				b.Fatalf("unexpected: files=%d bytes=%d", files, bytes)
			}
		}
	})
}
