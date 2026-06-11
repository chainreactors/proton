package runner

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
	"github.com/chainreactors/proton/sysinfo"
)

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

func shouldScanRegion(r sysinfo.MemoryRegion, opts memoryScanOptions) bool {
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

type sysRule struct {
	ID       string
	Name     string
	Severity string
	Request  *sys.Request
	FileReq  *file.Request // for expression-mode fallback
}

func buildSysScanner(rules []sysRule, execOpts *protocols.ExecuterOptions) *file.Scanner {
	var inputs []file.Rule
	for _, mr := range rules {
		var fileReqs []*file.Request
		if mr.FileReq != nil {
			fileReqs = []*file.Request{mr.FileReq}
		} else if mr.Request != nil && mr.Request.CompiledOperators != nil {
			req := &file.Request{
				Extensions: []string{"all"},
			}
			req.Matchers = mr.Request.Matchers
			req.Extractors = mr.Request.Extractors
			req.Compile(execOpts)
			fileReqs = []*file.Request{req}
		}
		if len(fileReqs) > 0 {
			inputs = append(inputs, file.Rule{
				ID:       mr.ID,
				Name:     mr.Name,
				Severity: mr.Severity,
				Requests: fileReqs,
			})
		}
	}
	if len(inputs) == 0 {
		return nil
	}
	return file.NewScanner(inputs, execOpts)
}

func scanProcessWithSysRules(rules []sysRule, execOpts *protocols.ExecuterOptions, pid int, callback func(file.Finding)) error {
	memoryRules := make([]sysRule, 0)
	dataRules := make([]sysRule, 0)
	for _, r := range rules {
		src := sysinfo.SourceMemory
		if r.Request != nil {
			src = r.Request.Source
		}
		if src == sysinfo.SourceMemory {
			memoryRules = append(memoryRules, r)
		} else {
			dataRules = append(dataRules, r)
		}
	}

	if len(dataRules) > 0 {
		dataScanner := buildSysScanner(dataRules, execOpts)
		if dataScanner != nil {
			for _, rule := range dataRules {
				src := rule.Request.Source
				data, err := sysinfo.ReadSource(pid, src)
				if err != nil || len(data) == 0 {
					continue
				}
				label := fmt.Sprintf("pid:%d:%s", pid, src)
				for _, group := range dataScanner.Groups {
					findings := dataScanner.ScanData(data, label, group)
					if len(findings) > 0 {
						atomic.AddInt64(&dataScanner.Stats.Findings, int64(len(findings)))
						for _, f := range findings {
							callback(f)
						}
					}
				}
			}
		}
	}

	if len(memoryRules) > 0 {
		sysScanner := buildSysScanner(memoryRules, execOpts)
		if sysScanner == nil {
			return nil
		}

		reader, err := sysinfo.NewMemoryReader(pid)
		if err != nil {
			return fmt.Errorf("cannot attach to pid %d: %w", pid, err)
		}
		defer reader.Close()

		regions, err := reader.Regions()
		if err != nil {
			return fmt.Errorf("cannot enumerate memory regions for pid %d: %w", pid, err)
		}

		var scanRegions []sysinfo.MemoryRegion
		for _, r := range regions {
			for _, mr := range memoryRules {
				if mr.Request != nil && mr.Request.MatchesRegion(r.Perms, r.MappedFile) {
					scanRegions = append(scanRegions, r)
					break
				}
				if mr.FileReq != nil && shouldScanRegion(r, memoryScanOptions{ScanAll: false}) {
					scanRegions = append(scanRegions, r)
					break
				}
			}
		}

		if len(scanRegions) > 0 {
			numWorkers := runtime.NumCPU()
			if numWorkers > len(scanRegions) {
				numWorkers = len(scanRegions)
			}

			type memJob struct {
				region sysinfo.MemoryRegion
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
						scanMemRegion(sysScanner, reader, job.region, label, job.group, &cbMu, callback)
					}
				}()
			}

			for _, region := range scanRegions {
				atomic.AddInt64(&sysScanner.Stats.Regions, 1)
				for _, group := range sysScanner.Groups {
					jobCh <- memJob{region: region, group: group}
				}
			}
			close(jobCh)
			wg.Wait()
		}
	}

	return nil
}

func scanProcess(scanner *file.Scanner, pid int, opts memoryScanOptions, callback func(file.Finding)) error {
	reader, err := sysinfo.NewMemoryReader(pid)
	if err != nil {
		return fmt.Errorf("cannot attach to pid %d: %w", pid, err)
	}
	defer reader.Close()

	regions, err := reader.Regions()
	if err != nil {
		return fmt.Errorf("cannot enumerate memory regions for pid %d: %w", pid, err)
	}

	var scanRegions []sysinfo.MemoryRegion
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
		region sysinfo.MemoryRegion
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

func scanMemRegion(scanner *file.Scanner, reader sysinfo.MemoryReader, region sysinfo.MemoryRegion, label string, group *file.ScanGroup, cbMu *sync.Mutex, callback func(file.Finding)) {
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
