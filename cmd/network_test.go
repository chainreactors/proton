package cmd

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/stretchr/testify/assert"
)

func testNetScanner(patterns []string) *file.Scanner {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: false},
	}
	req := &file.Request{Extensions: []string{"all"}}
	req.Extractors = []*operators.Extractor{
		{Type: "regex", Regex: patterns},
	}
	req.Compile(execOpts)
	return file.NewScanner([]file.Rule{{
		ID: "net-test", Name: "Net Test", Severity: "high",
		Requests: []*file.Request{req},
	}}, execOpts)
}

func TestStreamTrackerBasic(t *testing.T) {
	scanner := testNetScanner([]string{`password=\S+`})
	var findings []file.Finding
	tracker := newStreamTracker(scanner, func(f file.Finding) {
		findings = append(findings, f)
	})

	key := connKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 80,
	}

	// SYN
	tracker.processPacket(packetInfo{
		SrcIP: key.SrcIP, DstIP: key.DstIP,
		SrcPort: key.SrcPort, DstPort: key.DstPort,
		Seq: 100, Flags: tcpSYN,
	})

	// Data with secret
	tracker.processPacket(packetInfo{
		SrcIP: key.SrcIP, DstIP: key.DstIP,
		SrcPort: key.SrcPort, DstPort: key.DstPort,
		Seq: 101, Flags: tcpACK,
		Payload: []byte("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=Secret123!\r\n"),
	})

	// FIN triggers flush
	tracker.processPacket(packetInfo{
		SrcIP: key.SrcIP, DstIP: key.DstIP,
		SrcPort: key.SrcPort, DstPort: key.DstPort,
		Seq: 201, Flags: tcpFIN | tcpACK,
	})

	assert.True(t, len(findings) > 0, "should find password in stream")
	found := false
	for _, f := range findings {
		for _, e := range f.Extracts {
			if e.Value == "password=Secret123!" {
				found = true
			}
		}
	}
	assert.True(t, found, "should extract password=Secret123!")
}

func TestStreamTrackerRetransmission(t *testing.T) {
	scanner := testNetScanner([]string{`SECRET_[A-Z]+`})
	var findings []file.Finding
	tracker := newStreamTracker(scanner, func(f file.Finding) {
		findings = append(findings, f)
	})

	pkt := packetInfo{
		SrcIP: [4]byte{1, 1, 1, 1}, DstIP: [4]byte{2, 2, 2, 2},
		SrcPort: 1000, DstPort: 80,
		Seq: 100, Flags: tcpACK,
		Payload: []byte("SECRET_ALPHA"),
	}

	tracker.processPacket(pkt)
	// retransmit same seq
	tracker.processPacket(pkt)

	tracker.flushAll()

	extractCount := 0
	for _, f := range findings {
		extractCount += len(f.Extracts)
	}
	assert.Equal(t, 1, extractCount, "retransmission should not duplicate")
}

func TestStreamTrackerFlushAll(t *testing.T) {
	scanner := testNetScanner([]string{`TOKEN_[A-Z0-9]+`})
	var findings []file.Finding
	tracker := newStreamTracker(scanner, func(f file.Finding) {
		findings = append(findings, f)
	})

	tracker.processPacket(packetInfo{
		SrcIP: [4]byte{1, 1, 1, 1}, DstIP: [4]byte{2, 2, 2, 2},
		SrcPort: 5000, DstPort: 80,
		Seq: 0, Flags: tcpACK,
		Payload: []byte("Authorization: TOKEN_ABC123DEF456"),
	})

	tracker.flushAll()

	assert.True(t, len(findings) > 0)
	assert.True(t, len(tracker.conns) == 0, "flushAll should clear all connections")
}

func TestConnKeyLabel(t *testing.T) {
	key := connKey{
		SrcIP: [4]byte{192, 168, 1, 100}, DstIP: [4]byte{10, 0, 0, 1},
		SrcPort: 12345, DstPort: 80,
	}
	assert.Equal(t, "net:192.168.1.100:12345->10.0.0.1:80", key.label())
}

func TestShouldScanRegionCmd(t *testing.T) {
	tests := []struct {
		name   string
		region memoryRegion
		all    bool
		want   bool
	}{
		{"writable heap", memoryRegion{Perms: "rw-p", MappedFile: "[heap]"}, false, true},
		{"readonly code", memoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, false, false},
		{"readonly code with scanall", memoryRegion{Perms: "r-xp", MappedFile: "/lib/libc.so"}, true, true},
		{"no read perm", memoryRegion{Perms: "---p"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanRegion(tt.region, memoryScanOptions{ScanAll: tt.all})
			assert.Equal(t, tt.want, got)
		})
	}
}
