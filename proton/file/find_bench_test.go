package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/charlievieth/fastwalk"
	"github.com/gobwas/glob"
)

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
