package file

import (
	"fmt"
	"testing"
)

const lineCount = 1000

func BenchmarkDSLMap(b *testing.B) {
	sampleLines := make([]string, lineCount)
	for i := range sampleLines {
		sampleLines[i] = fmt.Sprintf("line-%d-payload-data-placeholder", i)
	}

	b.Run("NewPerLine", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, line := range sampleLines {
				m := make(map[string]interface{}, 4)
				m["raw"] = line
				m["type"] = "file"
				m["matched"] = false
				m["length"] = len(line)
				_ = m
			}
		}
	})

	b.Run("Reuse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m := make(map[string]interface{}, 4)
			m["type"] = "file"
			m["matched"] = false
			m["length"] = 0
			for _, line := range sampleLines {
				m["raw"] = line
				_ = m
			}
		}
	})
}
