//go:build linux
// +build linux

package cmd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readProcessEnv(pid int) ([]byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil, err
	}
	// null-separated → newline-separated for line-based matching
	return bytes.ReplaceAll(data, []byte{0}, []byte{'\n'}), nil
}

func readProcessCmdline(pid int) ([]byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(data, []byte{0}, []byte{' '}), nil
}

func readProcessFDs(pid int) ([]byte, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("fd/%s -> %s", entry.Name(), target))
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func readProcessConns(pid int) ([]byte, error) {
	var lines []string
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := fmt.Sprintf("/proc/%d/net/%s", pid, proto)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			local := parseHexAddr(fields[1])
			remote := parseHexAddr(fields[2])
			if remote == "" || remote == "0.0.0.0:0" || remote == "[::]:0" {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s local=%s remote=%s", proto, local, remote))
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func parseHexAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	hexIP := parts[0]
	hexPort := parts[1]

	port, _ := strconv.ParseUint(hexPort, 16, 16)

	if len(hexIP) == 8 {
		// IPv4: stored in little-endian hex
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			b[3-i] = byte(v)
		}
		return fmt.Sprintf("%s:%d", net.IP(b).String(), port)
	}
	return fmt.Sprintf("%s:%d", hexIP, port)
}

func readProcessPipes(pid int) ([]byte, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "pipe:") || strings.Contains(target, "fifo") {
			lines = append(lines, fmt.Sprintf("fd/%s -> %s", entry.Name(), target))
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}
