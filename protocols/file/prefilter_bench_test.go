package file

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

var literal = []byte("PRIVATE KEY")

func buildLines(n int) [][]byte {
	lines := make([][]byte, n)
	for i := range lines {
		if i%100 == 0 { // 1% of lines contain the literal
			lines[i] = []byte(strings.Repeat("x", 34) + "PRIVATE KEY" + strings.Repeat("x", 35))
		} else {
			lines[i] = []byte(strings.Repeat("abcdefgh", 10)) // 80 chars
		}
	}
	return lines
}

func BenchmarkPrefilter(b *testing.B) {
	missLine := []byte(strings.Repeat("abcdefgh", 10))
	hitLine := []byte(strings.Repeat("x", 34) + "PRIVATE KEY" + strings.Repeat("x", 35))

	b.Run("MayMatch/miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bytes.Contains(missLine, literal)
		}
	})

	b.Run("MayMatch/hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bytes.Contains(hitLine, literal)
		}
	})
}

func BenchmarkScanLine(b *testing.B) {
	for _, lineCount := range []int{12, 1250} { // ~1KB (12*80), ~100KB (1250*80)
		label := fmt.Sprintf("%dKB", lineCount*80/1024)
		if lineCount*80 < 1024 {
			label = "1KB"
		}
		lines := buildLines(lineCount)

		b.Run(fmt.Sprintf("NoPrefilter/%s", label), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					m := make(map[string]interface{}, 4)
					m["raw"] = string(line)
					m["type"] = "file"
					m["matched"] = false
					m["length"] = len(line)
					_ = m
				}
			}
		})

		b.Run(fmt.Sprintf("WithPrefilter/%s", label), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					if !bytes.Contains(line, literal) {
						continue
					}
					m := make(map[string]interface{}, 4)
					m["raw"] = string(line)
					m["type"] = "file"
					m["matched"] = true
					m["length"] = len(line)
					_ = m
				}
			}
		})
	}
}
