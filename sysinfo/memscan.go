package sysinfo

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
)

type MemScanOptions struct {
	ScanAll     bool
	OverlapSize int
	ChunkSize   int
	RegionFilter func(MemoryRegion) bool
}

const (
	DefaultChunkSize      = 4 << 20 // 4MB
	DefaultOverlapSize    = 512
	DefaultMaxRegionRead  = 64 << 20 // 64MB
)

func ShouldScanRegion(r MemoryRegion, scanAll bool) bool {
	if !strings.Contains(r.Perms, "r") {
		return false
	}
	if scanAll {
		return true
	}
	if strings.Contains(r.Perms, "w") {
		return true
	}
	if r.MappedFile == "" || r.MappedFile == "[heap]" || r.MappedFile == "[stack]" ||
		strings.HasPrefix(r.MappedFile, "[") {
		return true
	}
	return false
}

var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, DefaultChunkSize+DefaultOverlapSize)
		return &buf
	},
}

// WalkProcessMemory opens a process's memory, enumerates regions matching the
// filter, and calls onChunk for each data chunk read. Chunks include overlap
// bytes from the previous read to avoid missing matches at boundaries.
func WalkProcessMemory(pid int, opts MemScanOptions, onChunk func(data []byte, label string)) error {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = DefaultChunkSize
	}
	if opts.OverlapSize <= 0 {
		opts.OverlapSize = DefaultOverlapSize
	}

	reader, err := NewMemoryReader(pid)
	if err != nil {
		return fmt.Errorf("cannot attach to pid %d: %w", pid, err)
	}
	defer reader.Close()

	regions, err := reader.Regions()
	if err != nil {
		return fmt.Errorf("cannot enumerate memory regions for pid %d: %w", pid, err)
	}

	filter := opts.RegionFilter
	if filter == nil {
		filter = func(r MemoryRegion) bool {
			return ShouldScanRegion(r, opts.ScanAll)
		}
	}

	var scanRegions []MemoryRegion
	for _, r := range regions {
		if filter(r) {
			scanRegions = append(scanRegions, r)
		}
	}
	if len(scanRegions) == 0 {
		return nil
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > len(scanRegions) {
		numWorkers = len(scanRegions)
	}

	jobCh := make(chan MemoryRegion, numWorkers*16)
	var cbMu sync.Mutex
	var wg sync.WaitGroup
	label := fmt.Sprintf("pid:%d", pid)
	chunkSize := uint64(opts.ChunkSize)
	overlapSize := opts.OverlapSize

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bufPtr := readBufPool.Get().(*[]byte)
			buf := *bufPtr
			if uint64(len(buf)) < chunkSize+uint64(overlapSize) {
				buf = make([]byte, chunkSize+uint64(overlapSize))
			}
			defer readBufPool.Put(bufPtr)

			for region := range jobCh {
				walkRegion(reader, region, chunkSize, overlapSize, buf, label, &cbMu, onChunk)
			}
		}()
	}

	for _, region := range scanRegions {
		jobCh <- region
	}
	close(jobCh)
	wg.Wait()
	return nil
}

func walkRegion(reader MemoryReader, region MemoryRegion, chunkSize uint64, overlapSize int, buf []byte, label string, cbMu *sync.Mutex, onChunk func([]byte, string)) {
	regionSize := region.Size
	if regionSize > DefaultMaxRegionRead {
		regionSize = DefaultMaxRegionRead
	}
	if chunkSize > regionSize {
		chunkSize = regionSize
	}

	for offset := uint64(0); offset < regionSize; {
		readSize := chunkSize
		if offset+readSize > regionSize {
			readSize = regionSize - offset
		}
		readStart := region.BaseAddr + offset
		actualReadSize := readSize
		if offset > 0 && offset >= uint64(overlapSize) {
			readStart = region.BaseAddr + offset - uint64(overlapSize)
			actualReadSize = readSize + uint64(overlapSize)
		}
		if actualReadSize > uint64(len(buf)) {
			actualReadSize = uint64(len(buf))
		}

		n, err := reader.ReadAt(buf[:actualReadSize], readStart)
		if err != nil || n == 0 {
			offset += readSize
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		cbMu.Lock()
		onChunk(data, label)
		cbMu.Unlock()

		offset += readSize
	}
}
