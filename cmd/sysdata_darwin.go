//go:build darwin
// +build darwin

package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readProcessEnv(pid int) ([]byte, error) {
	data, err := sysctl_procargs2(pid)
	if err != nil {
		return nil, fmt.Errorf("read env for pid %d: %w", pid, err)
	}
	_, env := splitProcargs2(data)
	return []byte(strings.Join(env, "\n")), nil
}

func readProcessCmdline(pid int) ([]byte, error) {
	data, err := sysctl_procargs2(pid)
	if err != nil {
		return nil, fmt.Errorf("read cmdline for pid %d: %w", pid, err)
	}
	args, _ := splitProcargs2(data)
	return []byte(strings.Join(args, " ")), nil
}

// sysctl_procargs2 reads KERN_PROCARGS2 which returns:
// [argc (4 bytes)] [exec_path\0] [args separated by \0] [\0+] [env separated by \0]
func sysctl_procargs2(pid int) ([]byte, error) {
	mib := [3]int32{1, 49, int32(pid)} // CTL_KERN, KERN_PROCARGS2, pid
	size := uintptr(0)
	_, _, errno := unix.Syscall6(unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), 3,
		0, uintptr(unsafe.Pointer(&size)), 0, 0)
	if errno != 0 || size == 0 {
		return nil, fmt.Errorf("sysctl size: %v", errno)
	}
	buf := make([]byte, size)
	_, _, errno = unix.Syscall6(unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), 3,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("sysctl read: %v", errno)
	}
	return buf[:size], nil
}

func splitProcargs2(data []byte) (args []string, env []string) {
	if len(data) < 4 {
		return nil, nil
	}
	argc := int(*(*int32)(unsafe.Pointer(&data[0])))
	rest := data[4:]

	// skip exec path (first null-terminated string)
	idx := bytes.IndexByte(rest, 0)
	if idx < 0 {
		return nil, nil
	}
	rest = rest[idx+1:]

	// skip padding nulls
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}

	// parse args
	parts := bytes.Split(rest, []byte{0})
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		s := string(p)
		if i < argc {
			args = append(args, s)
		} else {
			env = append(env, s)
		}
	}
	return args, env
}

func readProcessFDs(pid int) ([]byte, error) {
	out, err := exec.Command("lsof", "-p", fmt.Sprintf("%d", pid), "-Fn").CombinedOutput()
	if err != nil {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") {
			lines = append(lines, line[1:])
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func readProcessConns(pid int) ([]byte, error) {
	out, err := exec.Command("lsof", "-i", "-p", fmt.Sprintf("%d", pid), "-Fn", "-nP").CombinedOutput()
	if err != nil {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") {
			lines = append(lines, line[1:])
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func readProcessPipes(pid int) ([]byte, error) {
	out, err := exec.Command("lsof", "-p", fmt.Sprintf("%d", pid), "-Fn").CombinedOutput()
	if err != nil {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") && strings.Contains(line, "FIFO") {
			lines = append(lines, line[1:])
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}
