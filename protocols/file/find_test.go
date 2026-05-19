package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/neutron/protocols"
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
