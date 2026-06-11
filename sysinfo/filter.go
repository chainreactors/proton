package sysinfo

import (
	"fmt"
	"net"
)

// MatchUserFilter applies a simple user-specified filter to a packet.
// Supported filters: "port N" and "host X.X.X.X".
// Returns true if the packet matches (or if the filter is unrecognised).
func MatchUserFilter(filter string, pkt PacketInfo) bool {
	// simple "port N" filter
	var port uint16
	if n, _ := fmt.Sscanf(filter, "port %d", &port); n == 1 {
		return pkt.SrcPort == port || pkt.DstPort == port
	}
	// "host X.X.X.X"
	var host string
	if n, _ := fmt.Sscanf(filter, "host %s", &host); n == 1 {
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return true
		}
		var addr [4]byte
		copy(addr[:], ip)
		return pkt.SrcIP == addr || pkt.DstIP == addr
	}
	return true
}
