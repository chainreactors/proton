package sysinfo

import (
	"bytes"
	"os/exec"
	"strings"
)

// GitDeletedBlobs finds files that were deleted from git history and returns
// their content via git show. Calls onBlob(data, label) for each deleted file's
// content. Requires git CLI. Returns nil if git is not available.
func GitDeletedBlobs(repoDir string, onBlob func(data []byte, label string)) error {
	if _, err := exec.LookPath("git"); err != nil {
		return err
	}

	out, err := exec.Command("git", "-C", repoDir,
		"log", "--all", "--diff-filter=D", "--name-only", "--pretty=format:%H").Output()
	if err != nil {
		return err
	}

	var currentCommit string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) == 40 && !strings.Contains(line, "/") {
			currentCommit = line
			continue
		}
		if currentCommit == "" {
			continue
		}
		key := currentCommit + ":" + line
		if seen[key] {
			continue
		}
		seen[key] = true

		blob, err := exec.Command("git", "-C", repoDir, "show", key).Output()
		if err != nil || len(blob) == 0 {
			continue
		}
		if isBinaryContent(blob) {
			continue
		}
		label := "git:" + repoDir + ":" + line + "@" + currentCommit[:8]
		onBlob(blob, label)
	}
	return nil
}

func isBinaryContent(data []byte) bool {
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	return bytes.Contains(sample, []byte{0})
}
