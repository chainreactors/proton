package file

import (
	"io"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

func testScanner(patterns []string) *Scanner {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req := &Request{Extensions: []string{"all"}}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: patterns},
	}
	req.Compile(execOpts)
	return NewScanner([]Rule{{
		ID: "test", Name: "Test", Severity: "high",
		Requests: []*Request{req},
	}}, execOpts)
}

func TestLineWriterBasic(t *testing.T) {
	scanner := testScanner([]string{`SECRET_[A-Z0-9]+`})
	var findings []Finding
	w := scanner.NewLineWriter("test:env", func(f Finding) {
		findings = append(findings, f)
	})

	w.Write([]byte("PATH=/usr/bin\n"))
	w.Write([]byte("SECRET_ABC123\n"))
	w.Write([]byte("HOME=/home/user\n"))
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find SECRET_ABC123")
	}
	found := false
	for _, f := range findings {
		for _, e := range f.Extracts {
			if e.Value == "SECRET_ABC123" {
				found = true
			}
		}
	}
	if !found {
		t.Error("should extract SECRET_ABC123")
	}
}

func TestLineWriterSplitChunks(t *testing.T) {
	scanner := testScanner([]string{`password=\S+`})
	var findings []Finding
	w := scanner.NewLineWriter("test:stream", func(f Finding) {
		findings = append(findings, f)
	})

	// Write across chunk boundary
	w.Write([]byte("user=admin\npass"))
	w.Write([]byte("word=Secret12"))
	w.Write([]byte("3\nother=data\n"))
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find password=Secret123 split across chunks")
	}
}

func TestLineWriterFlushOnClose(t *testing.T) {
	scanner := testScanner([]string{`TOKEN_[A-Z]+`})
	var findings []Finding
	w := scanner.NewLineWriter("test:close", func(f Finding) {
		findings = append(findings, f)
	})

	w.Write([]byte("TOKEN_ALPHA"))
	// No trailing newline — Close should flush
	w.Close()

	if len(findings) == 0 {
		t.Fatal("Close should flush incomplete line")
	}
}

func TestLineWriterIOCopy(t *testing.T) {
	scanner := testScanner([]string{`AKIA[A-Z0-9]{16}`})
	var findings []Finding
	w := scanner.NewLineWriter("test:io", func(f Finding) {
		findings = append(findings, f)
	})

	r := strings.NewReader("config=true\naws_key=AKIAIOSFODNN7EXAMPLE\nend\n")
	io.Copy(w, r)
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find AKIA key via io.Copy")
	}
}

func TestBlockWriterBasic(t *testing.T) {
	scanner := testScanner([]string{`PRIVATE_KEY_[A-Z0-9]+`})
	var findings []Finding
	w := scanner.NewBlockWriter("test:mem", func(f Finding) {
		findings = append(findings, f)
	})

	data := make([]byte, 1024)
	copy(data[500:], []byte("PRIVATE_KEY_ABC123"))
	w.Write(data)
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find PRIVATE_KEY_ABC123 in binary block")
	}
}

func TestBlockWriterLargeStream(t *testing.T) {
	scanner := testScanner([]string{`NEEDLE_[0-9]+`})
	var findings []Finding
	w := scanner.NewBlockWriter("test:large", func(f Finding) {
		findings = append(findings, f)
	})

	// Write multiple windows worth of data with a needle in the middle
	chunk := make([]byte, MemWindowSize)
	w.Write(chunk)
	needle := []byte("NEEDLE_42")
	w.Write(needle)
	w.Write(chunk)
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find NEEDLE_42 in large stream")
	}
}

func TestBlockWriterIOCopy(t *testing.T) {
	scanner := testScanner([]string{`BLOCK_SECRET`})
	var findings []Finding
	w := scanner.NewBlockWriter("test:copy", func(f Finding) {
		findings = append(findings, f)
	})

	data := make([]byte, 256)
	copy(data[100:], []byte("BLOCK_SECRET"))
	r := strings.NewReader(string(data))
	io.Copy(w, r)
	w.Close()

	if len(findings) == 0 {
		t.Fatal("should find BLOCK_SECRET via io.Copy")
	}
}
