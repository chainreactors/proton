//go:build windows

package sysinfo

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsSysinfoSmokeMemory(t *testing.T) {
	marker := []byte(fmt.Sprintf("PROTON_SYSINFO_WINDOWS_MEMORY_%d", time.Now().UnixNano()))
	reader, err := NewMemoryReader(os.Getpid())
	if err != nil {
		t.Fatalf("NewMemoryReader: %v", err)
	}
	regions, err := reader.Regions()
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatalf("Close memory reader: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("Regions: %v", err)
	}
	if len(regions) == 0 {
		t.Fatal("expected at least one readable memory region")
	}

	found := false
	err = WalkProcessMemory(os.Getpid(), MemScanOptions{}, func(data []byte, label string) {
		if !strings.HasPrefix(label, "pid:") {
			t.Fatalf("unexpected memory label: %s", label)
		}
		if bytes.Contains(data, marker) {
			found = true
		}
	})
	if err != nil {
		t.Fatalf("WalkProcessMemory: %v", err)
	}
	runtime.KeepAlive(marker)
	if !found {
		t.Fatal("memory marker not found")
	}
}

func TestWindowsSysinfoSmokeEnvCmdline(t *testing.T) {
	marker := fmt.Sprintf("PROTON_SYSINFO_SMOKE_%d", time.Now().UnixNano())
	child := exec.Command(os.Args[0], "-test.run=TestWindowsSysinfoSmokeHelper", "--", "sleep", marker)
	child.Env = append(os.Environ(),
		"GO_WANT_PROTON_SYSINFO_HELPER=1",
		marker+"=present",
	)
	if err := child.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer stopProcess(child.Process)

	env, err := ReadProcessEnv(child.Process.Pid)
	if err != nil {
		t.Fatalf("ReadProcessEnv: %v", err)
	}
	if !strings.Contains(string(env), marker+"=present") {
		t.Fatalf("env marker not found for pid %d", child.Process.Pid)
	}

	cmdline, err := ReadProcessCmdline(child.Process.Pid)
	if err != nil {
		t.Fatalf("ReadProcessCmdline: %v", err)
	}
	if !strings.Contains(string(cmdline), marker) {
		t.Fatalf("cmdline marker not found for pid %d", child.Process.Pid)
	}
}

func TestWindowsSysinfoSmokeConns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	child := exec.Command(os.Args[0], "-test.run=TestWindowsSysinfoSmokeHelper", "--", "dial", ln.Addr().String())
	child.Env = append(os.Environ(), "GO_WANT_PROTON_SYSINFO_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer stopProcess(child.Process)

	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not connect")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := ReadProcessConns(child.Process.Pid)
		if err != nil {
			t.Fatalf("ReadProcessConns: %v", err)
		}
		if strings.Contains(string(data), "tcp local=") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tcp connection not found for pid %d", child.Process.Pid)
}

func TestWindowsSysinfoSmokePipes(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\proton_sysinfo_smoke_%d`, time.Now().UnixNano())
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatalf("pipe name: %v", err)
	}
	h, err := windows.CreateNamedPipe(
		ptr,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateNamedPipe: %v", err)
	}
	defer windows.CloseHandle(h)

	data, err := ReadProcessPipes(os.Getpid())
	if err != nil {
		t.Fatalf("ReadProcessPipes: %v", err)
	}
	if !strings.Contains(string(data), name) {
		t.Fatalf("pipe marker not found")
	}
}

func TestWindowsSysinfoSmokeOpenCapture(t *testing.T) {
	ip := firstIPv4()
	if ip == "" {
		t.Skip("no IPv4 interface found")
	}
	handle, err := OpenCapture(ip)
	if err != nil {
		t.Logf("OpenCapture unavailable in current session: %v", err)
		return
	}
	defer handle.Close()
	buf := make([]byte, 65535)
	_, _ = handle.Read(buf)
}

func TestWindowsSysinfoSmokeHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PROTON_SYSINFO_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	switch args[1] {
	case "sleep":
		time.Sleep(30 * time.Second)
	case "dial":
		if len(args) < 3 {
			os.Exit(2)
		}
		conn, err := net.Dial("tcp", args[2])
		if err != nil {
			os.Exit(3)
		}
		defer conn.Close()
		time.Sleep(30 * time.Second)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func stopProcess(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
	_, _ = p.Wait()
}

func firstIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			return ipNet.IP.String()
		}
	}
	return ""
}
