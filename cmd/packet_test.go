package cmd

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func buildEthernetFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	// dst MAC
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// src MAC
	copy(frame[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4Packet(proto uint8, srcIP, dstIP [4]byte, payload []byte) []byte {
	ihl := 20
	totalLen := ihl + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // version=4, ihl=5
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
	binary.BigEndian.PutUint32(seg[8:12], 0) // ack
	seg[12] = byte(dataOffset/4) << 4        // data offset
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535) // window
	copy(seg[20:], payload)
	return seg
}

func TestParseEthernet(t *testing.T) {
	payload := []byte("test payload")
	frame := buildEthernetFrame(0x0800, payload)
	et, p, ok := parseEthernet(frame)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0800), et)
	assert.Equal(t, payload, p)
}

func TestParseEthernetVLAN(t *testing.T) {
	inner := []byte("inner")
	// 802.1Q: ethertype=0x8100, then 2 bytes TCI, then real ethertype
	vlan := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(vlan[0:2], 0x0001) // TCI
	binary.BigEndian.PutUint16(vlan[2:4], 0x0800)  // real ethertype
	copy(vlan[4:], inner)
	frame := buildEthernetFrame(0x8100, vlan)

	et, p, ok := parseEthernet(frame)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0800), et)
	assert.Equal(t, inner, p)
}

func TestParseEthernetTooShort(t *testing.T) {
	_, _, ok := parseEthernet([]byte{0x00, 0x01})
	assert.False(t, ok)
}

func TestParseIPv4(t *testing.T) {
	src := [4]byte{192, 168, 1, 1}
	dst := [4]byte{10, 0, 0, 1}
	tcp := buildTCPSegment(80, 12345, 1000, tcpACK, []byte("HTTP data"))
	ipPkt := buildIPv4Packet(6, src, dst, tcp)

	proto, parsedSrc, parsedDst, payload, ok := parseIPv4(ipPkt)
	assert.True(t, ok)
	assert.Equal(t, uint8(6), proto)
	assert.Equal(t, src, parsedSrc)
	assert.Equal(t, dst, parsedDst)
	assert.Equal(t, tcp, payload)
}

func TestParseIPv4TooShort(t *testing.T) {
	_, _, _, _, ok := parseIPv4([]byte{0x45, 0x00})
	assert.False(t, ok)
}

func TestParseIPv4BadVersion(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x65 // version 6
	_, _, _, _, ok := parseIPv4(pkt)
	assert.False(t, ok)
}

func TestParseTCP(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{5, 6, 7, 8}
	payload := []byte("password=secret123")
	seg := buildTCPSegment(8080, 443, 42, tcpACK, payload)

	info, ok := parseTCP(seg, src, dst)
	assert.True(t, ok)
	assert.Equal(t, uint16(8080), info.SrcPort)
	assert.Equal(t, uint16(443), info.DstPort)
	assert.Equal(t, uint32(42), info.Seq)
	assert.Equal(t, uint8(tcpACK), info.Flags)
	assert.Equal(t, payload, info.Payload)
	assert.Equal(t, src, info.SrcIP)
	assert.Equal(t, dst, info.DstIP)
}

func TestParseTCPSYN(t *testing.T) {
	seg := buildTCPSegment(1234, 80, 100, tcpSYN, nil)
	info, ok := parseTCP(seg, [4]byte{}, [4]byte{})
	assert.True(t, ok)
	assert.Equal(t, uint8(tcpSYN), info.Flags)
	assert.Empty(t, info.Payload)
}

func TestParseTCPTooShort(t *testing.T) {
	_, ok := parseTCP([]byte{0x00, 0x50}, [4]byte{}, [4]byte{})
	assert.False(t, ok)
}

func TestParseRawIP(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	payload := []byte("api_key=AKIATEST123456")
	tcp := buildTCPSegment(80, 54321, 500, tcpACK, payload)
	ip := buildIPv4Packet(6, src, dst, tcp)

	info, ok := parseRawIP(ip)
	assert.True(t, ok)
	assert.Equal(t, src, info.SrcIP)
	assert.Equal(t, dst, info.DstIP)
	assert.Equal(t, uint16(80), info.SrcPort)
	assert.Equal(t, uint16(54321), info.DstPort)
	assert.Equal(t, payload, info.Payload)
}

func TestParseRawIPNonTCP(t *testing.T) {
	ip := buildIPv4Packet(17, [4]byte{}, [4]byte{}, []byte("udp data")) // UDP
	_, ok := parseRawIP(ip)
	assert.False(t, ok)
}

func TestMatchUserFilter(t *testing.T) {
	pkt := packetInfo{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 80, DstPort: 54321,
	}
	assert.True(t, matchUserFilter("port 80", pkt))
	assert.True(t, matchUserFilter("port 54321", pkt))
	assert.False(t, matchUserFilter("port 443", pkt))
	assert.True(t, matchUserFilter("host 10.0.0.1", pkt))
	assert.False(t, matchUserFilter("host 10.0.0.3", pkt))
	assert.True(t, matchUserFilter("", pkt))
	assert.True(t, matchUserFilter("unknown filter", pkt))
}
