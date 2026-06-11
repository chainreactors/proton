//go:build darwin

package sysinfo

import (
	"os/exec"
	"strconv"
	"strings"
)

func listProcesses() ([]ProcessInfo, error) {
	out, err := exec.Command("ps", "-axo", "pid,comm").Output()
	if err != nil {
		return nil, err
	}
	var procs []ProcessInfo
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		procs = append(procs, ProcessInfo{PID: pid, Name: fields[1]})
	}
	return procs, nil
}
