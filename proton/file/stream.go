package file

import (
	"bytes"
	"sync/atomic"
)

// LineWriter wraps a Scanner for streaming text input. Incoming data is
// buffered and scanned line-by-line as complete lines arrive. Call Close()
// to flush the last incomplete line.
//
// Implements io.WriteCloser. Safe for single-goroutine use.
type LineWriter struct {
	scanner  *Scanner
	label    string
	callback func(Finding)
	buf      []byte
}

// NewLineWriter creates a streaming line-based scanner.
//
//	w := scanner.NewLineWriter("pid:1234:env", callback)
//	w.Write(chunk1)
//	w.Write(chunk2)
//	w.Close() // flush remaining
func (s *Scanner) NewLineWriter(label string, callback func(Finding)) *LineWriter {
	return &LineWriter{
		scanner:  s,
		label:    label,
		callback: callback,
	}
}

func (lw *LineWriter) Write(p []byte) (int, error) {
	lw.buf = append(lw.buf, p...)

	for {
		idx := bytes.IndexByte(lw.buf, '\n')
		if idx < 0 {
			break
		}
		line := lw.buf[:idx]
		lw.buf = lw.buf[idx+1:]

		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			continue
		}

		lw.scanLine(line)
	}

	return len(p), nil
}

func (lw *LineWriter) Close() error {
	if len(lw.buf) > 0 {
		lw.scanLine(lw.buf)
		lw.buf = nil
	}
	return nil
}

func (lw *LineWriter) scanLine(line []byte) {
	data := append(line, '\n')
	for _, group := range lw.scanner.Groups {
		findings := lw.scanner.ScanData(data, lw.label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&lw.scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				lw.callback(f)
			}
		}
	}
}

// BlockWriter wraps a Scanner for streaming binary input. Incoming data
// is buffered and scanned in fixed-size windows with overlap to catch
// matches spanning chunk boundaries. Call Close() to flush remaining data.
//
// Implements io.WriteCloser. Safe for single-goroutine use.
type BlockWriter struct {
	scanner    *Scanner
	label      string
	callback   func(Finding)
	buf        []byte
	windowSize int
	overlap    int
}

// NewBlockWriter creates a streaming block-based scanner.
//
//	w := scanner.NewBlockWriter("pid:1234", callback)
//	w.Write(memChunk1)
//	w.Write(memChunk2)
//	w.Close()
func (s *Scanner) NewBlockWriter(label string, callback func(Finding)) *BlockWriter {
	return &BlockWriter{
		scanner:    s,
		label:      label,
		callback:   callback,
		windowSize: MemWindowSize,
		overlap:    MemOverlapSize,
	}
}

func (bw *BlockWriter) Write(p []byte) (int, error) {
	bw.buf = append(bw.buf, p...)

	for len(bw.buf) >= bw.windowSize {
		window := bw.buf[:bw.windowSize]
		bw.scanWindow(window)

		advance := bw.windowSize - bw.overlap
		if advance <= 0 {
			advance = bw.windowSize
		}
		bw.buf = bw.buf[advance:]
	}

	return len(p), nil
}

func (bw *BlockWriter) Close() error {
	if len(bw.buf) > 0 {
		bw.scanWindow(bw.buf)
		bw.buf = nil
	}
	return nil
}

func (bw *BlockWriter) scanWindow(data []byte) {
	for _, group := range bw.scanner.Groups {
		findings := bw.scanner.ScanBlock(data, bw.label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&bw.scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				bw.callback(f)
			}
		}
	}
}
