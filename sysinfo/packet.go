package sysinfo

import "encoding/binary"

// PacketInfo holds parsed TCP/IP packet metadata and payload.
type PacketInfo struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Flags   uint8
	Payload []byte
}

// TCP flag constants.
const (
	TcpFIN = 0x01
	TcpSYN = 0x02
	TcpRST = 0x04
	TcpACK = 0x10
)

// ParseEthernet extracts the EtherType and payload from an Ethernet frame.
// It handles 802.1Q VLAN tags transparently.
func ParseEthernet(frame []byte) (etherType uint16, payload []byte, ok bool) {
	if len(frame) < 14 {
		return 0, nil, false
	}
	et := binary.BigEndian.Uint16(frame[12:14])
	payload = frame[14:]
	// 802.1Q VLAN tag
	if et == 0x8100 {
		if len(payload) < 4 {
			return 0, nil, false
		}
		et = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	return et, payload, true
}

// ParseIPv4 extracts protocol, source/destination IPs and payload from an IPv4 packet.
func ParseIPv4(pkt []byte) (proto uint8, srcIP, dstIP [4]byte, payload []byte, ok bool) {
	if len(pkt) < 20 {
		return 0, srcIP, dstIP, nil, false
	}
	version := pkt[0] >> 4
	if version != 4 {
		return 0, srcIP, dstIP, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, srcIP, dstIP, nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl {
		return 0, srcIP, dstIP, nil, false
	}
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	proto = pkt[9]
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])
	return proto, srcIP, dstIP, pkt[ihl:totalLen], true
}

// ParseTCP extracts TCP header fields and payload from a TCP segment.
func ParseTCP(seg []byte, srcIP, dstIP [4]byte) (info PacketInfo, ok bool) {
	if len(seg) < 20 {
		return info, false
	}
	dataOffset := int(seg[12]>>4) * 4
	if dataOffset < 20 || dataOffset > len(seg) {
		return info, false
	}
	info.SrcIP = srcIP
	info.DstIP = dstIP
	info.SrcPort = binary.BigEndian.Uint16(seg[0:2])
	info.DstPort = binary.BigEndian.Uint16(seg[2:4])
	info.Seq = binary.BigEndian.Uint32(seg[4:8])
	info.Flags = seg[13]
	if dataOffset < len(seg) {
		info.Payload = seg[dataOffset:]
	}
	return info, true
}

// ParseRawIP parses IP+TCP from a raw IP socket (no Ethernet header).
func ParseRawIP(pkt []byte) (info PacketInfo, ok bool) {
	proto, srcIP, dstIP, tcpSeg, ok := ParseIPv4(pkt)
	if !ok || proto != 6 {
		return info, false
	}
	return ParseTCP(tcpSeg, srcIP, dstIP)
}
