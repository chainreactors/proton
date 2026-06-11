package sysinfo

import (
	"encoding/binary"
	"testing"
)

func buildEthernetFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4Packet(proto uint8, srcIP, dstIP [4]byte, payload []byte) []byte {
	ihl := 20
	totalLen := ihl + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = proto
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	copy(pkt[20:], payload)
	return pkt
}

func buildTCPSegment(srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) []byte {
	dataOffset := 20
	seg := make([]byte, dataOffset+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], 0)
	seg[12] = byte(dataOffset/4) << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], payload)
	return seg
}

func TestParseEthernet(t *testing.T) {
	payload := []byte("test payload")
	frame := buildEthernetFrame(0x0800, payload)
	et, p, ok := ParseEthernet(frame)
	if !ok {
		t.Fatal("ParseEthernet failed")
	}
	if et != 0x0800 {
		t.Errorf("etherType = %x, want 0x0800", et)
	}
	if string(p) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestParseEthernetVLAN(t *testing.T) {
	inner := []byte("inner")
	vlan := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(vlan[0:2], 0x0001)
	binary.BigEndian.PutUint16(vlan[2:4], 0x0800)
	copy(vlan[4:], inner)
	frame := buildEthernetFrame(0x8100, vlan)

	et, p, ok := ParseEthernet(frame)
	if !ok || et != 0x0800 {
		t.Fatalf("VLAN parse: ok=%v et=%x", ok, et)
	}
	if string(p) != string(inner) {
		t.Error("VLAN payload mismatch")
	}
}

func TestParseEthernetTooShort(t *testing.T) {
	_, _, ok := ParseEthernet([]byte{0x00, 0x01})
	if ok {
		t.Error("should fail on short frame")
	}
}

func TestParseIPv4(t *testing.T) {
	src := [4]byte{192, 168, 1, 1}
	dst := [4]byte{10, 0, 0, 1}
	tcp := buildTCPSegment(80, 12345, 1000, TcpACK, []byte("data"))
	ip := buildIPv4Packet(6, src, dst, tcp)

	proto, s, d, payload, ok := ParseIPv4(ip)
	if !ok {
		t.Fatal("ParseIPv4 failed")
	}
	if proto != 6 || s != src || d != dst {
		t.Errorf("header mismatch: proto=%d src=%v dst=%v", proto, s, d)
	}
	if len(payload) != len(tcp) {
		t.Errorf("payload len = %d, want %d", len(payload), len(tcp))
	}
}

func TestParseIPv4TooShort(t *testing.T) {
	_, _, _, _, ok := ParseIPv4([]byte{0x45, 0x00})
	if ok {
		t.Error("should fail")
	}
}

func TestParseIPv4BadVersion(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x65
	_, _, _, _, ok := ParseIPv4(pkt)
	if ok {
		t.Error("should fail on version 6")
	}
}

func TestParseTCP(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{5, 6, 7, 8}
	payload := []byte("password=secret")
	seg := buildTCPSegment(8080, 443, 42, TcpACK, payload)

	info, ok := ParseTCP(seg, src, dst)
	if !ok {
		t.Fatal("ParseTCP failed")
	}
	if info.SrcPort != 8080 || info.DstPort != 443 {
		t.Errorf("ports: %d→%d", info.SrcPort, info.DstPort)
	}
	if info.Seq != 42 {
		t.Errorf("seq = %d", info.Seq)
	}
	if string(info.Payload) != string(payload) {
		t.Error("payload mismatch")
	}
}

func TestParseTCPTooShort(t *testing.T) {
	_, ok := ParseTCP([]byte{0x00, 0x50}, [4]byte{}, [4]byte{})
	if ok {
		t.Error("should fail")
	}
}

func TestParseRawIP(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	payload := []byte("api_key=AKIATEST")
	tcp := buildTCPSegment(80, 54321, 500, TcpACK, payload)
	ip := buildIPv4Packet(6, src, dst, tcp)

	info, ok := ParseRawIP(ip)
	if !ok {
		t.Fatal("ParseRawIP failed")
	}
	if info.SrcIP != src || info.DstIP != dst {
		t.Error("IP mismatch")
	}
	if string(info.Payload) != string(payload) {
		t.Error("payload mismatch")
	}
}

func TestParseRawIPNonTCP(t *testing.T) {
	ip := buildIPv4Packet(17, [4]byte{}, [4]byte{}, []byte("udp"))
	_, ok := ParseRawIP(ip)
	if ok {
		t.Error("should reject non-TCP")
	}
}

func TestMatchUserFilter(t *testing.T) {
	pkt := PacketInfo{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 80, DstPort: 54321,
	}
	if !MatchUserFilter("port 80", pkt) {
		t.Error("should match src port")
	}
	if !MatchUserFilter("port 54321", pkt) {
		t.Error("should match dst port")
	}
	if MatchUserFilter("port 443", pkt) {
		t.Error("should not match 443")
	}
	if !MatchUserFilter("host 10.0.0.1", pkt) {
		t.Error("should match src host")
	}
	if MatchUserFilter("host 10.0.0.3", pkt) {
		t.Error("should not match 10.0.0.3")
	}
	if !MatchUserFilter("", pkt) {
		t.Error("empty filter should pass all")
	}
}
