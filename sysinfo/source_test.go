//go:build linux

package sysinfo

import (
	"os"
	"strings"
	"testing"
)

func TestReadProcessEnv(t *testing.T) {
	data, err := ReadProcessEnv(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessEnv: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("env data should not be empty")
	}
	if !strings.Contains(string(data), "PATH=") {
		t.Error("env should contain PATH=")
	}
}

func TestReadProcessCmdline(t *testing.T) {
	data, err := ReadProcessCmdline(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessCmdline: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("cmdline should not be empty")
	}
}

func TestReadProcessFDs(t *testing.T) {
	data, err := ReadProcessFDs(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessFDs: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("fd list should not be empty (at least stdin/stdout/stderr)")
	}
	if !strings.Contains(string(data), "fd/") {
		t.Error("should contain fd/ entries")
	}
}

func TestReadProcessConns(t *testing.T) {
	data, err := ReadProcessConns(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessConns: %v", err)
	}
	_ = data
}

func TestReadProcessPipes(t *testing.T) {
	data, err := ReadProcessPipes(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessPipes: %v", err)
	}
	_ = data
}

func TestReadSourceDispatch(t *testing.T) {
	for _, src := range []string{SourceEnv, SourceCmdline, SourceFD, SourceConn, SourcePipe} {
		data, err := ReadSource(os.Getpid(), src)
		if err != nil {
			t.Errorf("ReadSource(%s): %v", src, err)
		}
		_ = data
	}

	_, err := ReadSource(os.Getpid(), "bogus")
	if err == nil {
		t.Error("ReadSource with unknown source should error")
	}
}
