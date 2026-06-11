package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// ShmPaths returns shared memory paths to scan.
func ShmPaths() []string {
	switch runtime.GOOS {
	case "linux":
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return []string{"/dev/shm"}
		}
	}
	return nil
}

// TmpfsPaths returns tmpfs/ramfs paths likely to contain sensitive data.
func TmpfsPaths() []string {
	var paths []string
	candidates := []string{
		"/tmp",
		"/run/secrets",
		"/var/run/secrets",
	}

	if uid := os.Getuid(); uid >= 0 {
		candidates = append(candidates, filepath.Join("/run/user", strconv.Itoa(uid)))
	}

	if runtime.GOOS == "windows" {
		candidates = []string{os.TempDir()}
	}

	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			paths = append(paths, p)
		}
	}
	return paths
}

// HistoryFiles returns shell/tool history files for the current user.
func HistoryFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	names := []string{
		".bash_history",
		".zsh_history",
		".sh_history",
		".fish_history",
		".python_history",
		".node_repl_history",
		".mysql_history",
		".psql_history",
		".rediscli_history",
		".mongosh",
		".sqlite_history",
		".irb_history",
		".lesshst",
	}

	var files []string
	for _, name := range names {
		p := filepath.Join(home, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			files = append(files, p)
		}
	}

	xdg := []string{
		filepath.Join(home, ".local", "share", "fish", "fish_history"),
	}
	for _, p := range xdg {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			files = append(files, p)
		}
	}

	return files
}
