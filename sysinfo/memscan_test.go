//go:build linux

package sysinfo

import (
	"os"
	"strings"
	"testing"
)

func TestShouldScanRegion(t *testing.T) {
	tests := []struct {
		name    string
		region  MemoryRegion
		scanAll bool
		want    bool
	}{
		{"writable heap", MemoryRegion{Perms: "rw-p", MappedFile: "[heap]"}, false, true},
		{"readonly code", MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, false, false},
		{"readonly+scanall", MemoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, true, true},
		{"no read perm", MemoryRegion{Perms: "---p"}, false, false},
		{"anon writable", MemoryRegion{Perms: "rw-p", MappedFile: ""}, false, true},
		{"stack", MemoryRegion{Perms: "rw-p", MappedFile: "[stack]"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldScanRegion(tt.region, tt.scanAll)
			if got != tt.want {
				t.Errorf("ShouldScanRegion(%+v, %v) = %v, want %v", tt.region, tt.scanAll, got, tt.want)
			}
		})
	}
}

func TestWalkProcessMemorySelf(t *testing.T) {
	pid := os.Getpid()
	_, err := NewMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own memory: %v", err)
	}

	var chunks int
	var totalBytes int
	err = WalkProcessMemory(pid, MemScanOptions{ScanAll: false}, func(data []byte, label string) {
		chunks++
		totalBytes += len(data)
		if !strings.HasPrefix(label, "pid:") {
			t.Errorf("label should start with pid:, got %s", label)
		}
	})
	if err != nil {
		t.Fatalf("WalkProcessMemory: %v", err)
	}
	if chunks == 0 {
		t.Error("should have read at least one chunk from self process")
	}
	t.Logf("read %d chunks, %d bytes total", chunks, totalBytes)
}

func TestWalkProcessMemoryWithFilter(t *testing.T) {
	pid := os.Getpid()
	_, err := NewMemoryReader(pid)
	if err != nil {
		t.Skipf("cannot read own memory: %v", err)
	}

	var chunks int
	opts := MemScanOptions{
		RegionFilter: func(r MemoryRegion) bool {
			return r.MappedFile == "[heap]"
		},
	}
	err = WalkProcessMemory(pid, opts, func(data []byte, label string) {
		chunks++
	})
	if err != nil {
		t.Fatalf("WalkProcessMemory with filter: %v", err)
	}
	t.Logf("heap-only: %d chunks", chunks)
}

func TestWalkProcessMemoryBadPid(t *testing.T) {
	err := WalkProcessMemory(999999999, MemScanOptions{}, func(data []byte, label string) {
		t.Error("should not be called")
	})
	if err == nil {
		t.Error("expected error for invalid pid")
	}
}

func TestParseMapsLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		ok     bool
		base   uint64
		perms  string
		mapped string
	}{
		{"heap", "7f1234560000-7f1234570000 rw-p 00000000 00:00 0                          [heap]", true, 0x7f1234560000, "rw-p", "[heap]"},
		{"lib", "7f0000100000-7f0000200000 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6", true, 0x7f0000100000, "r-xp", "/usr/lib/libc.so.6"},
		{"empty", "", false, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, ok := ParseMapsLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok {
				if region.BaseAddr != tt.base {
					t.Errorf("BaseAddr = %x, want %x", region.BaseAddr, tt.base)
				}
				if region.Perms != tt.perms {
					t.Errorf("Perms = %q, want %q", region.Perms, tt.perms)
				}
				if region.MappedFile != tt.mapped {
					t.Errorf("MappedFile = %q, want %q", region.MappedFile, tt.mapped)
				}
			}
		})
	}
}

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"0100007F:0050", "127.0.0.1:80"},
		{"00000000:0000", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseHexAddr(tt.input)
			if got != tt.expect {
				t.Errorf("ParseHexAddr(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}
