package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"github.com/charlievieth/fastwalk"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/require"
)

func newTestOptions() *protocols.ExecuterOptions {
	return &protocols.ExecuterOptions{Options: &protocols.Options{}}
}

func newTextOnlyOptions() *protocols.ExecuterOptions {
	return &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: true}}
}

func TestFindInputPaths(t *testing.T) {
	request := &Request{
		ID:          "testing-file",
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all", ".lock"},
		DenyList:    []string{".go"},
	}
	err := request.Compile(newTestOptions())
	require.Nil(t, err, "could not compile file request")

	tempDir, err := os.MkdirTemp("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	files := map[string]string{
		"test.go":           "TEST",
		"config.yaml":       "TEST",
		"final.yaml":        "TEST",
		"image_ignored.png": "TEST",
		"test.js":           "TEST",
	}
	for k, v := range files {
		err = os.WriteFile(filepath.Join(tempDir, k), []byte(v), os.ModePerm)
		require.Nil(t, err, "could not write temporary file")
	}

	expected := []string{"config.yaml", "final.yaml", "test.js"}

	t.Run("glob", func(t *testing.T) {
		var got []string
		err = request.getInputPaths(tempDir+"/*", func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Nil(t, err, "could not get input paths for glob")
		require.ElementsMatch(t, expected, got, "could not get correct file matches for glob")
	})

	t.Run("directory", func(t *testing.T) {
		var got []string
		err = request.getInputPaths(tempDir, func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Nil(t, err, "could not get input paths for directory")
		require.ElementsMatch(t, expected, got, "could not get correct file matches for directory")
	})
}

func TestIsTextContent(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		require.True(t, isTextContent([]byte{}))
	})
	t.Run("plain_text", func(t *testing.T) {
		require.True(t, isTextContent([]byte("hello world\nfoo bar\n")))
	})
	t.Run("text_with_tabs", func(t *testing.T) {
		require.True(t, isTextContent([]byte("func main() {\n\tfmt.Println()\n}\n")))
	})
	t.Run("json", func(t *testing.T) {
		require.True(t, isTextContent([]byte(`{"key": "value", "num": 123}`)))
	})
	t.Run("binary_null_bytes", func(t *testing.T) {
		require.False(t, isTextContent([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x00, 0x1A}))
	})
	t.Run("binary_exe", func(t *testing.T) {
		data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
		require.False(t, isTextContent(data))
	})
	t.Run("binary_many_control_chars", func(t *testing.T) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i % 32)
		}
		require.False(t, isTextContent(data))
	})
	t.Run("utf8_text", func(t *testing.T) {
		require.True(t, isTextContent([]byte("你好世界 hello world\n")))
	})
}

func TestValidatePathTextOnly(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "textonly-*")
	require.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files
	os.WriteFile(filepath.Join(tempDir, "config.yaml"), []byte("key: value\n"), 0644)
	os.WriteFile(filepath.Join(tempDir, "script.py"), []byte("import os\n"), 0644)
	os.WriteFile(filepath.Join(tempDir, "data.bin"), []byte{0x00, 0x01, 0x02, 0x03, 0xFF}, 0644)
	os.WriteFile(filepath.Join(tempDir, "Makefile"), []byte("all:\n\techo hello\n"), 0644)
	os.WriteFile(filepath.Join(tempDir, "unknown.xyz"), []byte("this is actually text\n"), 0644)
	os.WriteFile(filepath.Join(tempDir, "binary.xyz"), []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x0A}, 0644)

	t.Run("textonly_off", func(t *testing.T) {
		request := &Request{
			ID:         "test",
			MaxSize:    "1Gb",
			Extensions: []string{"all"},
		}
		err := request.Compile(newTestOptions())
		require.Nil(t, err)

		var got []string
		request.getInputPaths(tempDir, func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Contains(t, got, "data.bin", "TextOnly off should include binary files")
		require.Contains(t, got, "binary.xyz", "TextOnly off should include binary .xyz")
	})

	t.Run("textonly_on", func(t *testing.T) {
		request := &Request{
			ID:         "test",
			MaxSize:    "1Gb",
			Extensions: []string{"all"},
		}
		err := request.Compile(newTextOnlyOptions())
		require.Nil(t, err)

		var got []string
		request.getInputPaths(tempDir, func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Contains(t, got, "config.yaml", "should include .yaml (quick path)")
		require.Contains(t, got, "script.py", "should include .py (quick path)")
		require.Contains(t, got, "Makefile", "should include no-extension files")
		require.Contains(t, got, "unknown.xyz", "should include text .xyz (pre-check)")
		require.NotContains(t, got, "data.bin", "should skip binary .bin (pre-check)")
		require.NotContains(t, got, "binary.xyz", "should skip binary .xyz (pre-check)")
	})

	t.Run("textonly_with_specific_extensions", func(t *testing.T) {
		request := &Request{
			ID:         "test",
			MaxSize:    "1Gb",
			Extensions: []string{".yaml"},
		}
		err := request.Compile(newTextOnlyOptions())
		require.Nil(t, err)

		var got []string
		request.getInputPaths(tempDir, func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Equal(t, []string{"config.yaml"}, got, "specific extensions should ignore TextOnly")
	})

	t.Run("textonly_with_scan_all", func(t *testing.T) {
		request := &Request{
			ID:         "test",
			MaxSize:    "1Gb",
			Extensions: []string{"all"},
			ScanAll:    true,
		}
		err := request.Compile(newTextOnlyOptions())
		require.Nil(t, err)

		var got []string
		request.getInputPaths(tempDir, func(item string) {
			got = append(got, filepath.Base(item))
		})
		require.Contains(t, got, "data.bin", "scan-all should include binary files")
	})
}

// createTestTree creates a temporary directory tree with numFiles files spread
// across depth levels. Files use a rotating set of extensions so that ~10% are
// .go files. Returns the root path.
func createTestTree(b *testing.B, numFiles, depth int) string {
	b.Helper()
	root := b.TempDir()

	extensions := []string{".go", ".txt", ".yaml", ".json", ".py", ".js", ".md", ".xml", ".html", ".css"}
	filesPerLevel := numFiles / depth
	if filesPerLevel < 1 {
		filesPerLevel = 1
	}

	for d := 0; d < depth; d++ {
		dir := root
		for i := 0; i <= d; i++ {
			dir = filepath.Join(dir, fmt.Sprintf("level%d", i))
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatal(err)
		}
		for f := 0; f < filesPerLevel; f++ {
			ext := extensions[(d*filesPerLevel+f)%len(extensions)]
			name := filepath.Join(dir, fmt.Sprintf("file_%d_%d%s", d, f, ext))
			if err := os.WriteFile(name, []byte("// placeholder content\n"), 0644); err != nil {
				b.Fatal(err)
			}
		}
	}
	return root
}

// createFlatDir creates a flat directory with numFiles files, using the same
// rotating extension set so that ~10% have the .go extension.
func createFlatDir(b *testing.B, numFiles int) string {
	b.Helper()
	root := b.TempDir()

	extensions := []string{".go", ".txt", ".yaml", ".json", ".py", ".js", ".md", ".xml", ".html", ".css"}
	for i := 0; i < numFiles; i++ {
		ext := extensions[i%len(extensions)]
		name := filepath.Join(root, fmt.Sprintf("file_%05d%s", i, ext))
		if err := os.WriteFile(name, []byte("// placeholder\n"), 0644); err != nil {
			b.Fatal(err)
		}
	}
	return root
}

func BenchmarkWalk(b *testing.B) {
	sizes := []struct {
		name  string
		files int
		depth int
	}{
		{"1000files", 1000, 10},
		{"10000files", 10000, 20},
	}

	for _, sz := range sizes {
		root := createTestTree(b, sz.files, sz.depth)

		b.Run("StdLib/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var count int64
				_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if !d.IsDir() {
						count++
					}
					return nil
				})
				_ = count
			}
		})

		b.Run("Fastwalk/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var count atomic.Int64
				_ = fastwalk.Walk(nil, root, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if !d.IsDir() {
						count.Add(1)
					}
					return nil
				})
				_ = count.Load()
			}
		})
	}
}

func BenchmarkGlob(b *testing.B) {
	const numFiles = 1000
	root := createFlatDir(b, numFiles)

	b.Run("StdLib_Glob", func(b *testing.B) {
		pattern := filepath.Join(root, "*.go")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			matches, _ := filepath.Glob(pattern)
			_ = matches
		}
	})

	b.Run("Fastwalk_Glob", func(b *testing.B) {
		compiled, err := glob.Compile("*.go")
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var mu sync.Mutex
			var matches []string
			_ = fastwalk.Walk(nil, root, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if d.IsDir() {
					return nil
				}
				if compiled.Match(filepath.Base(path)) {
					mu.Lock()
					matches = append(matches, path)
					mu.Unlock()
				}
				return nil
			})
			_ = matches
		}
	})
}

func BenchmarkGlobCompile(b *testing.B) {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"simple_star", "*.go"},
		{"double_star", "**/*.go"},
		{"complex", "src/**/*.{go,js,py}"},
	}
	for _, p := range patterns {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				g, err := glob.Compile(p.pattern)
				if err != nil {
					b.Fatal(err)
				}
				_ = g
			}
		})
	}
}
