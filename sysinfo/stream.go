package sysinfo

import (
	"fmt"
	"net"
	"sync"
	"time"
)

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
	DefaultMaxConnBufSize = 256 * 1024
	DefaultMaxConns       = 65536
	DefaultIdleTimeout    = 60
)

// StreamReassembler reassembles TCP streams from individual packets and
// delivers contiguous data chunks to a callback. It is scanner-agnostic —
// the callback receives raw bytes and a connection label.
type StreamReassembler struct {
	mu          sync.Mutex
	conns       map[connKey]*trackedConn
	onData      func(data []byte, label string)
	bufPool     sync.Pool
	overlapSize int
	windowSize  int
	maxBufSize  int
}

// NewStreamReassembler creates a reassembler that calls onData whenever a
// stream buffer is flushed. overlapSize bytes from the end of each flush
// are retained so boundary-spanning matches are not missed. windowSize is
// the buffer threshold that triggers a flush.
func NewStreamReassembler(onData func(data []byte, label string), overlapSize, windowSize int) *StreamReassembler {
	if overlapSize <= 0 {
		overlapSize = DefaultOverlapSize
	}
	if windowSize <= 0 {
		windowSize = 32 * 1024
	}
	maxBuf := DefaultMaxConnBufSize
	return &StreamReassembler{
		conns:       make(map[connKey]*trackedConn),
		onData:      onData,
		overlapSize: overlapSize,
		windowSize:  windowSize,
		maxBufSize:  maxBuf,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, maxBuf)
				return &buf
			},
		},
	}
}

func (sr *StreamReassembler) getBuf() []byte {
	return *sr.bufPool.Get().(*[]byte)
}

func (sr *StreamReassembler) putBuf(buf []byte) {
	sr.bufPool.Put(&buf)
}

func (sr *StreamReassembler) ProcessPacket(pkt PacketInfo) {
	if len(pkt.Payload) == 0 && pkt.Flags&(TcpSYN|TcpFIN|TcpRST) == 0 {
		return
	}

	fwdKey := connKey{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	revKey := fwdKey.reverse()

	sr.mu.Lock()
	conn, exists := sr.conns[fwdKey]
	if !exists {
		conn = sr.conns[revKey]
	}

	if pkt.Flags&TcpSYN != 0 && !exists {
		if len(sr.conns) >= DefaultMaxConns {
			sr.evictOldestLocked()
		}
		conn = &trackedConn{key: fwdKey, label: fwdKey.label()}
		conn.forward.buf = sr.getBuf()
		conn.reverse.buf = sr.getBuf()
		sr.conns[fwdKey] = conn
		sr.conns[revKey] = conn
	}

	if conn == nil {
		if len(pkt.Payload) == 0 {
			sr.mu.Unlock()
			return
		}
		if len(sr.conns) >= DefaultMaxConns {
			sr.evictOldestLocked()
		}
		conn = &trackedConn{key: fwdKey, label: fwdKey.label()}
		conn.forward.buf = sr.getBuf()
		conn.reverse.buf = sr.getBuf()
		sr.conns[fwdKey] = conn
		sr.conns[revKey] = conn
	}

	conn.lastSeen = time.Now().Unix()

	var stream *connStream
	if fwdKey == conn.key {
		stream = &conn.forward
	} else {
		stream = &conn.reverse
	}
	sr.mu.Unlock()

	if pkt.Flags&TcpSYN != 0 {
		stream.nextSeq = pkt.Seq + 1
		stream.seqValid = true
		return
	}

	if pkt.Flags&(TcpFIN|TcpRST) != 0 {
		if len(pkt.Payload) > 0 {
			sr.appendPayload(stream, pkt.Payload, pkt.Seq, conn.label)
		}
		sr.flushStream(stream, conn.label)
		if pkt.Flags&TcpRST != 0 {
			sr.removeConn(fwdKey)
		}
		return
	}

	if len(pkt.Payload) > 0 {
		sr.appendPayload(stream, pkt.Payload, pkt.Seq, conn.label)
	}
}

func (sr *StreamReassembler) appendPayload(stream *connStream, payload []byte, seq uint32, label string) {
	if stream.seqValid {
		if seq < stream.nextSeq {
			return
		}
		stream.nextSeq = seq + uint32(len(payload))
	} else {
		stream.nextSeq = seq + uint32(len(payload))
		stream.seqValid = true
	}

	n := len(payload)
	if stream.bufLen+n > sr.maxBufSize {
		sr.flushStream(stream, label)
	}
	if n > sr.maxBufSize {
		sr.onData(payload, label)
		return
	}

	copy(stream.buf[stream.bufLen:], payload)
	stream.bufLen += n

	if stream.bufLen >= sr.windowSize {
		sr.flushStream(stream, label)
	}
}

func (sr *StreamReassembler) flushStream(stream *connStream, label string) {
	if stream.bufLen == 0 {
		return
	}
	data := make([]byte, stream.bufLen)
	copy(data, stream.buf[:stream.bufLen])
	sr.onData(data, label)

	if stream.bufLen > sr.overlapSize {
		copy(stream.buf, stream.buf[stream.bufLen-sr.overlapSize:stream.bufLen])
		stream.bufLen = sr.overlapSize
	} else {
		stream.bufLen = 0
	}
}

func (sr *StreamReassembler) evictOldestLocked() {
	var oldestKey connKey
	oldestTime := int64(1<<63 - 1)
	for k, c := range sr.conns {
		if c.lastSeen < oldestTime {
			oldestTime = c.lastSeen
			oldestKey = k
		}
	}
	if conn, ok := sr.conns[oldestKey]; ok {
		sr.flushStream(&conn.forward, conn.label)
		sr.flushStream(&conn.reverse, conn.label)
		sr.putBuf(conn.forward.buf)
		sr.putBuf(conn.reverse.buf)
		delete(sr.conns, conn.key)
		delete(sr.conns, conn.key.reverse())
	}
}

func (sr *StreamReassembler) removeConn(key connKey) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	conn, ok := sr.conns[key]
	if !ok {
		conn = sr.conns[key.reverse()]
	}
	if conn == nil {
		return
	}
	sr.putBuf(conn.forward.buf)
	sr.putBuf(conn.reverse.buf)
	delete(sr.conns, conn.key)
	delete(sr.conns, conn.key.reverse())
}

func (sr *StreamReassembler) ExpireIdle(maxAge int64) {
	now := time.Now().Unix()
	sr.mu.Lock()
	defer sr.mu.Unlock()

	var toRemove []connKey
	seen := make(map[connKey]bool)
	for k, c := range sr.conns {
		if seen[k] {
			continue
		}
		seen[k] = true
		seen[k.reverse()] = true
		if now-c.lastSeen > maxAge {
			sr.flushStream(&c.forward, c.label)
			sr.flushStream(&c.reverse, c.label)
			toRemove = append(toRemove, c.key)
		}
	}
	for _, k := range toRemove {
		if conn, ok := sr.conns[k]; ok {
			sr.putBuf(conn.forward.buf)
			sr.putBuf(conn.reverse.buf)
		}
		delete(sr.conns, k)
		delete(sr.conns, k.reverse())
	}
}

func (sr *StreamReassembler) FlushAll() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	seen := make(map[connKey]bool)
	for k, c := range sr.conns {
		if seen[k] {
			continue
		}
		seen[k] = true
		seen[k.reverse()] = true
		sr.flushStream(&c.forward, c.label)
		sr.flushStream(&c.reverse, c.label)
		sr.putBuf(c.forward.buf)
		sr.putBuf(c.reverse.buf)
	}
	sr.conns = make(map[connKey]*trackedConn)
}
