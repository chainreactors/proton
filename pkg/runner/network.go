package runner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/sysinfo"
)

type networkOpts struct {
	Interface string
	BPFFilter string
}

type connKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

func (k connKey) reverse() connKey {
	return connKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort}
}

func (k connKey) label() string {
	src := net.IP(k.SrcIP[:]).String()
	dst := net.IP(k.DstIP[:]).String()
	return fmt.Sprintf("net:%s:%d->%s:%d", src, k.SrcPort, dst, k.DstPort)
}

type connStream struct {
	buf      []byte
	bufLen   int
	nextSeq  uint32
	seqValid bool
}

type trackedConn struct {
	key      connKey
	forward  connStream
	reverse  connStream
	label    string
	lastSeen int64
}

const (
	maxConnBufSize = 256 * 1024
	maxConns       = 65536
	idleTimeout    = 60
)

type streamTracker struct {
	mu       sync.Mutex
	conns    map[connKey]*trackedConn
	scanner  *file.Scanner
	callback func(file.Finding)
	bufPool  sync.Pool
}

func newStreamTracker(scanner *file.Scanner, callback func(file.Finding)) *streamTracker {
	return &streamTracker{
		conns:    make(map[connKey]*trackedConn),
		scanner:  scanner,
		callback: callback,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, maxConnBufSize)
				return &buf
			},
		},
	}
}

func (st *streamTracker) getBuf() []byte {
	return *st.bufPool.Get().(*[]byte)
}

func (st *streamTracker) putBuf(buf []byte) {
	st.bufPool.Put(&buf)
}

func (st *streamTracker) processPacket(pkt sysinfo.PacketInfo) {
	if len(pkt.Payload) == 0 && pkt.Flags&(sysinfo.TcpSYN|sysinfo.TcpFIN|sysinfo.TcpRST) == 0 {
		return
	}

	fwdKey := connKey{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	revKey := fwdKey.reverse()

	st.mu.Lock()
	conn, exists := st.conns[fwdKey]
	if !exists {
		conn = st.conns[revKey]
	}

	if pkt.Flags&sysinfo.TcpSYN != 0 && !exists {
		if len(st.conns) >= maxConns {
			st.evictOldestLocked()
		}
		conn = &trackedConn{
			key:   fwdKey,
			label: fwdKey.label(),
		}
		conn.forward.buf = st.getBuf()
		conn.reverse.buf = st.getBuf()
		st.conns[fwdKey] = conn
		st.conns[revKey] = conn
	}

	if conn == nil {
		if len(pkt.Payload) == 0 {
			st.mu.Unlock()
			return
		}
		if len(st.conns) >= maxConns {
			st.evictOldestLocked()
		}
		conn = &trackedConn{
			key:   fwdKey,
			label: fwdKey.label(),
		}
		conn.forward.buf = st.getBuf()
		conn.reverse.buf = st.getBuf()
		st.conns[fwdKey] = conn
		st.conns[revKey] = conn
	}

	conn.lastSeen = time.Now().Unix()

	var stream *connStream
	if fwdKey == conn.key {
		stream = &conn.forward
	} else {
		stream = &conn.reverse
	}
	st.mu.Unlock()

	if pkt.Flags&sysinfo.TcpSYN != 0 {
		stream.nextSeq = pkt.Seq + 1
		stream.seqValid = true
		return
	}

	if pkt.Flags&(sysinfo.TcpFIN|sysinfo.TcpRST) != 0 {
		if len(pkt.Payload) > 0 {
			st.appendPayload(stream, pkt.Payload, pkt.Seq, conn.label)
		}
		st.flushStream(stream, conn.label)
		if pkt.Flags&sysinfo.TcpRST != 0 {
			st.removeConn(fwdKey)
		}
		return
	}

	if len(pkt.Payload) > 0 {
		st.appendPayload(stream, pkt.Payload, pkt.Seq, conn.label)
	}
}

func (st *streamTracker) appendPayload(stream *connStream, payload []byte, seq uint32, label string) {
	if stream.seqValid {
		if seq < stream.nextSeq {
			return // retransmission
		}
		stream.nextSeq = seq + uint32(len(payload))
	} else {
		stream.nextSeq = seq + uint32(len(payload))
		stream.seqValid = true
	}

	n := len(payload)
	if stream.bufLen+n > maxConnBufSize {
		st.flushStream(stream, label)
	}
	if n > maxConnBufSize {
		// payload larger than buffer: scan directly
		for _, group := range st.scanner.Groups {
			findings := st.scanner.ScanBlock(payload, label, group)
			for _, f := range findings {
				st.callback(f)
			}
		}
		return
	}

	copy(stream.buf[stream.bufLen:], payload)
	stream.bufLen += n

	if stream.bufLen >= file.MemWindowSize {
		st.flushStream(stream, label)
	}
}

func (st *streamTracker) flushStream(stream *connStream, label string) {
	if stream.bufLen == 0 {
		return
	}
	data := stream.buf[:stream.bufLen]
	for _, group := range st.scanner.Groups {
		findings := st.scanner.ScanBlock(data, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&st.scanner.Stats.Findings, int64(len(findings)))
			for _, f := range findings {
				st.callback(f)
			}
		}
	}
	overlap := file.MemOverlapSize
	if stream.bufLen > overlap {
		copy(stream.buf, stream.buf[stream.bufLen-overlap:stream.bufLen])
		stream.bufLen = overlap
	} else {
		stream.bufLen = 0
	}
}

func (st *streamTracker) evictOldestLocked() {
	var oldestKey connKey
	oldestTime := int64(1<<63 - 1)
	for k, c := range st.conns {
		if c.lastSeen < oldestTime {
			oldestTime = c.lastSeen
			oldestKey = k
		}
	}
	if conn, ok := st.conns[oldestKey]; ok {
		st.flushStream(&conn.forward, conn.label)
		st.flushStream(&conn.reverse, conn.label)
		st.putBuf(conn.forward.buf)
		st.putBuf(conn.reverse.buf)
		delete(st.conns, conn.key)
		delete(st.conns, conn.key.reverse())
	}
}

func (st *streamTracker) removeConn(key connKey) {
	st.mu.Lock()
	defer st.mu.Unlock()
	conn, ok := st.conns[key]
	if !ok {
		conn = st.conns[key.reverse()]
	}
	if conn == nil {
		return
	}
	st.putBuf(conn.forward.buf)
	st.putBuf(conn.reverse.buf)
	delete(st.conns, conn.key)
	delete(st.conns, conn.key.reverse())
}

func (st *streamTracker) expireIdle(maxAge int64) {
	now := time.Now().Unix()
	st.mu.Lock()
	defer st.mu.Unlock()

	var toRemove []connKey
	seen := make(map[connKey]bool)
	for k, c := range st.conns {
		if seen[k] {
			continue
		}
		seen[k] = true
		seen[k.reverse()] = true
		if now-c.lastSeen > maxAge {
			st.flushStream(&c.forward, c.label)
			st.flushStream(&c.reverse, c.label)
			toRemove = append(toRemove, c.key)
		}
	}
	for _, k := range toRemove {
		if conn, ok := st.conns[k]; ok {
			st.putBuf(conn.forward.buf)
			st.putBuf(conn.reverse.buf)
		}
		delete(st.conns, k)
		delete(st.conns, k.reverse())
	}
}

func (st *streamTracker) flushAll() {
	st.mu.Lock()
	defer st.mu.Unlock()
	seen := make(map[connKey]bool)
	for k, c := range st.conns {
		if seen[k] {
			continue
		}
		seen[k] = true
		seen[k.reverse()] = true
		st.flushStream(&c.forward, c.label)
		st.flushStream(&c.reverse, c.label)
		st.putBuf(c.forward.buf)
		st.putBuf(c.reverse.buf)
	}
	st.conns = make(map[connKey]*trackedConn)
}

func scanNetwork(ctx context.Context, scanner *file.Scanner, opts networkOpts, callback func(file.Finding)) error {
	handle, err := sysinfo.OpenCapture(opts.Interface)
	if err != nil {
		return err
	}
	defer handle.Close()

	tracker := newStreamTracker(scanner, callback)

	buf := make([]byte, 65536)
	hasEth := handle.HasEthernetHeader()

	lastExpire := time.Now()

	for {
		select {
		case <-ctx.Done():
			tracker.flushAll()
			return ctx.Err()
		default:
		}

		n, err := handle.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				tracker.flushAll()
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
				continue // only IPv4 for now
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

		tracker.processPacket(pkt)

		if time.Since(lastExpire) > 10*time.Second {
			tracker.expireIdle(idleTimeout)
			lastExpire = time.Now()
		}
	}
}
