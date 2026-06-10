package cmd

import "encoding/binary"

type packetInfo struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Flags   uint8
	Payload []byte
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

func parseEthernet(frame []byte) (etherType uint16, payload []byte, ok bool) {
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

func parseIPv4(pkt []byte) (proto uint8, srcIP, dstIP [4]byte, payload []byte, ok bool) {
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

func parseTCP(seg []byte, srcIP, dstIP [4]byte) (info packetInfo, ok bool) {
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

// parseRawIP parses IP+TCP from a raw IP socket (no Ethernet header).
func parseRawIP(pkt []byte) (info packetInfo, ok bool) {
	proto, srcIP, dstIP, tcpSeg, ok := parseIPv4(pkt)
	if !ok || proto != 6 {
		return info, false
	}
	return parseTCP(tcpSeg, srcIP, dstIP)
}
