package runner

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
)

type networkOpts struct {
	Interface string
	BPFFilter string
}

func scanNetwork(ctx context.Context, scanner *file.Scanner, opts networkOpts, callback func(file.Finding)) error {
	handle, err := sysinfo.OpenCapture(opts.Interface)
	if err != nil {
		return err
	}
	defer handle.Close()

	reassembler := sysinfo.NewStreamReassembler(func(data []byte, label string) {
		for _, group := range scanner.Groups {
			findings := scanner.ScanBlock(data, label, group)
			if len(findings) > 0 {
				atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
				for _, f := range findings {
					callback(f)
				}
			}
		}
	}, file.MemOverlapSize, file.MemWindowSize)

	buf := make([]byte, 65536)
	hasEth := handle.HasEthernetHeader()
	lastExpire := time.Now()

	for {
		select {
		case <-ctx.Done():
			reassembler.FlushAll()
			return ctx.Err()
		default:
		}

		n, err := handle.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				reassembler.FlushAll()
				return ctx.Err()
			default:
			}
			continue
		}
		if n == 0 {
			continue
		}

		atomic.AddInt64(&scanner.Stats.Packets, 1)
		atomic.AddInt64(&scanner.Stats.Bytes, int64(n))

		var pkt sysinfo.PacketInfo
		var ok bool

		if hasEth {
			etherType, ipPkt, ethOk := sysinfo.ParseEthernet(buf[:n])
			if !ethOk || etherType != 0x0800 {
				continue
			}
			proto, srcIP, dstIP, tcpSeg, ipOk := sysinfo.ParseIPv4(ipPkt)
			if !ipOk || proto != 6 {
				continue
			}
			pkt, ok = sysinfo.ParseTCP(tcpSeg, srcIP, dstIP)
		} else {
			pkt, ok = sysinfo.ParseRawIP(buf[:n])
		}

		if !ok {
			continue
		}

		if opts.BPFFilter != "" {
			if !sysinfo.MatchUserFilter(opts.BPFFilter, pkt) {
				continue
			}
		}

		reassembler.ProcessPacket(pkt)

		if time.Since(lastExpire) > 10*time.Second {
			reassembler.ExpireIdle(sysinfo.DefaultIdleTimeout)
			lastExpire = time.Now()
		}
	}
}
