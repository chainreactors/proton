//go:build linux
// +build linux

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type linuxMemReader struct {
	pid     int
	memFile *os.File
}

func newMemoryReader(pid int) (memoryReader, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w (requires root or same user)", memPath, err)
	}
	return &linuxMemReader{pid: pid, memFile: f}, nil
}

func (r *linuxMemReader) Regions() ([]memoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", r.pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []memoryRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		region, ok := parseMapsLine(scanner.Text())
		if ok {
			regions = append(regions, region)
		}
	}
	return regions, scanner.Err()
}

func parseMapsLine(line string) (memoryRegion, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return memoryRegion{}, false
	}

	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return memoryRegion{}, false
	}

	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return memoryRegion{}, false
	}
	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return memoryRegion{}, false
	}

	perms := fields[1]
	mappedFile := ""
	if len(fields) >= 6 {
		mappedFile = fields[5]
	}

	return memoryRegion{
		BaseAddr:   start,
		Size:       end - start,
		Perms:      perms,
		MappedFile: mappedFile,
	}, true
}

func (r *linuxMemReader) ReadAt(buf []byte, addr uint64) (int, error) {
	return r.memFile.ReadAt(buf, int64(addr))
}

func (r *linuxMemReader) Close() error {
	return r.memFile.Close()
}
