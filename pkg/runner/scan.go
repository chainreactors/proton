package runner

import (
	"sync/atomic"

	"github.com/chainreactors/proton/proton/file"
)

func scanData(scanner *file.Scanner, data []byte, label string, callback func(file.Finding)) {
	for _, group := range scanner.Groups {
		findings := scanner.ScanData(data, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				callback(f)
			}
		}
	}
}

func scanBlock(scanner *file.Scanner, data []byte, label string, callback func(file.Finding)) {
	for _, group := range scanner.Groups {
		findings := scanner.ScanBlock(data, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				callback(f)
			}
		}
	}
}
