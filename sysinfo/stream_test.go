package sysinfo

import (
	"strings"
	"sync"
	"testing"
)

func TestStreamReassemblerBasicFlow(t *testing.T) {
	var mu sync.Mutex
	var chunks []string
	sr := NewStreamReassembler(func(data []byte, label string) {
		mu.Lock()
		chunks = append(chunks, string(data))
		mu.Unlock()
	}, 64, 32*1024)

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}

	sr.ProcessPacket(PacketInfo{
		SrcIP: src, DstIP: dst, SrcPort: 1234, DstPort: 80,
		Seq: 100, Flags: TcpSYN,
	})

	sr.ProcessPacket(PacketInfo{
		SrcIP: src, DstIP: dst, SrcPort: 1234, DstPort: 80,
		Seq: 101, Flags: TcpACK,
		Payload: []byte("GET /secret?key=AKIA1234 HTTP/1.1\r\n"),
	})

	sr.ProcessPacket(PacketInfo{
		SrcIP: src, DstIP: dst, SrcPort: 1234, DstPort: 80,
		Seq: 200, Flags: TcpFIN | TcpACK,
	})

	found := false
	for _, c := range chunks {
		if strings.Contains(c, "AKIA1234") {
			found = true
		}
	}
	if !found {
		t.Error("should find AKIA1234 in reassembled stream")
	}
}

func TestStreamReassemblerRetransmitDrop(t *testing.T) {
	var count int
	sr := NewStreamReassembler(func(data []byte, label string) {
		count += strings.Count(string(data), "UNIQUE")
	}, 64, 32*1024)

	pkt := PacketInfo{
		SrcIP: [4]byte{1, 1, 1, 1}, DstIP: [4]byte{2, 2, 2, 2},
		SrcPort: 5000, DstPort: 80,
		Seq: 100, Flags: TcpACK,
		Payload: []byte("UNIQUE_TOKEN_HERE"),
	}
	sr.ProcessPacket(pkt)
	sr.ProcessPacket(pkt) // retransmit — same seq
	sr.FlushAll()

	if count != 1 {
		t.Errorf("expected 1 occurrence after retransmit, got %d", count)
	}
}

func TestStreamReassemblerFlushAll(t *testing.T) {
	var chunks int
	sr := NewStreamReassembler(func(data []byte, label string) {
		chunks++
	}, 64, 32*1024)

	for i := 0; i < 5; i++ {
		sr.ProcessPacket(PacketInfo{
			SrcIP: [4]byte{byte(i), 0, 0, 1}, DstIP: [4]byte{byte(i), 0, 0, 2},
			SrcPort: uint16(1000 + i), DstPort: 80,
			Seq: 0, Flags: TcpACK,
			Payload: []byte("data for stream"),
		})
	}

	sr.FlushAll()
	if chunks < 5 {
		t.Errorf("FlushAll should deliver all buffered streams, got %d chunks", chunks)
	}
}

func TestStreamReassemblerExpireIdle(t *testing.T) {
	var chunks int
	sr := NewStreamReassembler(func(data []byte, label string) {
		chunks++
	}, 64, 32*1024)

	sr.ProcessPacket(PacketInfo{
		SrcIP: [4]byte{1, 0, 0, 1}, DstIP: [4]byte{1, 0, 0, 2},
		SrcPort: 2000, DstPort: 80,
		Seq: 0, Flags: TcpACK,
		Payload: []byte("old stream data"),
	})

	// Force lastSeen to be old
	sr.mu.Lock()
	for _, c := range sr.conns {
		c.lastSeen = 0
	}
	sr.mu.Unlock()

	sr.ExpireIdle(1)

	if chunks == 0 {
		t.Error("ExpireIdle should flush expired streams")
	}
}

func TestStreamReassemblerBidirectional(t *testing.T) {
	var labels []string
	sr := NewStreamReassembler(func(data []byte, label string) {
		labels = append(labels, label)
	}, 64, 32*1024)

	client := [4]byte{10, 0, 0, 1}
	server := [4]byte{10, 0, 0, 2}

	// client → server
	sr.ProcessPacket(PacketInfo{
		SrcIP: client, DstIP: server, SrcPort: 4000, DstPort: 80,
		Seq: 100, Flags: TcpSYN,
	})
	sr.ProcessPacket(PacketInfo{
		SrcIP: client, DstIP: server, SrcPort: 4000, DstPort: 80,
		Seq: 101, Flags: TcpACK,
		Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})

	// server → client (reverse direction)
	sr.ProcessPacket(PacketInfo{
		SrcIP: server, DstIP: client, SrcPort: 80, DstPort: 4000,
		Seq: 500, Flags: TcpACK,
		Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
	})

	sr.FlushAll()

	if len(labels) < 2 {
		t.Errorf("should have flushed both directions, got %d flushes", len(labels))
	}
}
