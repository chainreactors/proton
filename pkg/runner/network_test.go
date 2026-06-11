//go:build linux
// +build linux

package runner

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
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

func scannerReassembler(scanner *file.Scanner, findings *[]file.Finding) *sysinfo.StreamReassembler {
	return sysinfo.NewStreamReassembler(func(data []byte, label string) {
		for _, group := range scanner.Groups {
			for _, f := range scanner.ScanBlock(data, label, group) {
				*findings = append(*findings, f)
			}
		}
	}, file.MemOverlapSize, file.MemWindowSize)
}

func TestStreamReassemblerBasic(t *testing.T) {
	scanner := testNetScanner([]string{`password=\S+`})
	var findings []file.Finding
	reassembler := scannerReassembler(scanner, &findings)

	key := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}

	reassembler.ProcessPacket(sysinfo.PacketInfo{
		SrcIP: key, DstIP: dst, SrcPort: 12345, DstPort: 80,
		Seq: 100, Flags: sysinfo.TcpSYN,
	})

	reassembler.ProcessPacket(sysinfo.PacketInfo{
		SrcIP: key, DstIP: dst, SrcPort: 12345, DstPort: 80,
		Seq: 101, Flags: sysinfo.TcpACK,
		Payload: []byte("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=Secret123!\r\n"),
	})

	reassembler.ProcessPacket(sysinfo.PacketInfo{
		SrcIP: key, DstIP: dst, SrcPort: 12345, DstPort: 80,
		Seq: 201, Flags: sysinfo.TcpFIN | sysinfo.TcpACK,
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

func TestStreamReassemblerRetransmission(t *testing.T) {
	scanner := testNetScanner([]string{`SECRET_[A-Z]+`})
	var findings []file.Finding
	reassembler := scannerReassembler(scanner, &findings)

	pkt := sysinfo.PacketInfo{
		SrcIP: [4]byte{1, 1, 1, 1}, DstIP: [4]byte{2, 2, 2, 2},
		SrcPort: 1000, DstPort: 80,
		Seq: 100, Flags: sysinfo.TcpACK,
		Payload: []byte("SECRET_ALPHA"),
	}

	reassembler.ProcessPacket(pkt)
	reassembler.ProcessPacket(pkt) // retransmit

	reassembler.FlushAll()

	extractCount := 0
	for _, f := range findings {
		extractCount += len(f.Extracts)
	}
	assert.Equal(t, 1, extractCount, "retransmission should not duplicate")
}

func TestStreamReassemblerFlushAll(t *testing.T) {
	scanner := testNetScanner([]string{`TOKEN_[A-Z0-9]+`})
	var findings []file.Finding
	reassembler := scannerReassembler(scanner, &findings)

	reassembler.ProcessPacket(sysinfo.PacketInfo{
		SrcIP: [4]byte{1, 1, 1, 1}, DstIP: [4]byte{2, 2, 2, 2},
		SrcPort: 5000, DstPort: 80,
		Seq: 0, Flags: sysinfo.TcpACK,
		Payload: []byte("Authorization: TOKEN_ABC123DEF456"),
	})

	reassembler.FlushAll()

	assert.True(t, len(findings) > 0)
}
