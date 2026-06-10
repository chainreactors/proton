package cmd

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/proton/proton/file"
)

type memoryRegion struct {
	BaseAddr   uint64
	Size       uint64
	Perms      string
	MappedFile string
}

type memoryReader interface {
	Regions() ([]memoryRegion, error)
	ReadAt(buf []byte, addr uint64) (int, error)
	Close() error
}

type memoryScanOptions struct {
	ScanAll bool
}

const (
	maxRegionReadSize  = 64 << 20
	maxRegionChunkSize = 4 << 20
)

var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, maxRegionChunkSize+file.MemOverlapSize)
		return &buf
	},
}

func shouldScanRegion(r memoryRegion, opts memoryScanOptions) bool {
	if !strings.Contains(r.Perms, "r") {
		return false
	}
	if opts.ScanAll {
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

func scanProcess(scanner *file.Scanner, pid int, opts memoryScanOptions, callback func(file.Finding)) error {
	reader, err := newMemoryReader(pid)
	if err != nil {
		return fmt.Errorf("cannot attach to pid %d: %w", pid, err)
	}
	defer reader.Close()

	regions, err := reader.Regions()
	if err != nil {
		return fmt.Errorf("cannot enumerate memory regions for pid %d: %w", pid, err)
	}

	var scanRegions []memoryRegion
	for _, r := range regions {
		if shouldScanRegion(r, opts) {
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

	type memJob struct {
		region memoryRegion
		group  *file.ScanGroup
	}
	jobCh := make(chan memJob, numWorkers*16)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	label := fmt.Sprintf("pid:%d", pid)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				scanMemRegion(scanner, reader, job.region, label, job.group, &cbMu, callback)
			}
		}()
	}

	for _, region := range scanRegions {
		atomic.AddInt64(&scanner.Stats.Regions, 1)
		for _, group := range scanner.Groups {
			jobCh <- memJob{region: region, group: group}
		}
	}
	close(jobCh)
	wg.Wait()
	return nil
}

func scanMemRegion(scanner *file.Scanner, reader memoryReader, region memoryRegion, label string, group *file.ScanGroup, cbMu *sync.Mutex, callback func(file.Finding)) {
	regionSize := region.Size
	if regionSize > maxRegionReadSize {
		regionSize = maxRegionReadSize
	}

	chunkSize := uint64(maxRegionChunkSize)
	if chunkSize > regionSize {
		chunkSize = regionSize
	}

	bufPtr := readBufPool.Get().(*[]byte)
	buf := *bufPtr
	if uint64(len(buf)) < chunkSize+uint64(file.MemOverlapSize) {
		buf = make([]byte, chunkSize+uint64(file.MemOverlapSize))
	}
	defer func() { readBufPool.Put(bufPtr) }()

	for offset := uint64(0); offset < regionSize; {
		readSize := chunkSize
		if offset+readSize > regionSize {
			readSize = regionSize - offset
		}
		readStart := region.BaseAddr + offset
		actualReadSize := readSize
		if offset > 0 && offset >= uint64(file.MemOverlapSize) {
			readStart = region.BaseAddr + offset - uint64(file.MemOverlapSize)
			actualReadSize = readSize + uint64(file.MemOverlapSize)
		}
		if actualReadSize > uint64(len(buf)) {
			actualReadSize = uint64(len(buf))
		}

		n, err := reader.ReadAt(buf[:actualReadSize], readStart)
		if err != nil || n == 0 {
			offset += readSize
			continue
		}

		data := buf[:n]
		atomic.AddInt64(&scanner.Stats.Bytes, int64(n))

		findings := scanner.ScanBlock(data, label, group)
		if len(findings) > 0 {
			atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
			cbMu.Lock()
			for _, f := range findings {
				callback(f)
			}
			cbMu.Unlock()
		}

		offset += readSize
	}
}
