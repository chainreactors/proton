//go:build linux
// +build linux

package file

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

func newMemoryReader(pid int) (MemoryReader, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w (requires root or same user)", memPath, err)
	}
	return &linuxMemReader{pid: pid, memFile: f}, nil
}

func (r *linuxMemReader) Regions() ([]MemoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", r.pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []MemoryRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		region, ok := parseMapsLine(scanner.Text())
		if ok {
			regions = append(regions, region)
		}
	}
	return regions, scanner.Err()
}

// parseMapsLine parses a line from /proc/pid/maps:
// 55a1b2c3d000-55a1b2c4e000 r-xp 00000000 08:01 1234  /usr/bin/foo
func parseMapsLine(line string) (MemoryRegion, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return MemoryRegion{}, false
	}

	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return MemoryRegion{}, false
	}

	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return MemoryRegion{}, false
	}
	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return MemoryRegion{}, false
	}

	perms := fields[1]
	mappedFile := ""
	if len(fields) >= 6 {
		mappedFile = fields[5]
	}

	return MemoryRegion{
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
