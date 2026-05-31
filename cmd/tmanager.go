package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/templates"
	"gopkg.in/yaml.v3"
)

const configFileName = "config.yaml"

type FoundConfig struct {
	TemplateURL string `yaml:"template-url,omitempty"`
	TemplateDir string `yaml:"template-dir,omitempty"`
}

func foundConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "found")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "found")
}

func defaultTemplateDir() string {
	return filepath.Join(foundConfigDir(), "templates")
}

func loadFoundConfig() *FoundConfig {
	cfg := &FoundConfig{}
	data, err := os.ReadFile(filepath.Join(foundConfigDir(), configFileName))
	if err != nil {
		return cfg
	}
	yaml.Unmarshal(data, cfg)
	return cfg
}

func saveFoundConfig(cfg *FoundConfig) error {
	dir := foundConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, configFileName), data, 0644)
}

func resolveTemplateDir(opts *Options) string {
	if opts.UpdateTemplateDir != "" {
		return opts.UpdateTemplateDir
	}
	cfg := loadFoundConfig()
	if cfg.TemplateDir != "" {
		return cfg.TemplateDir
	}
	return defaultTemplateDir()
}

func resolveTemplateURL(opts *Options) string {
	if opts.TemplateURL != "" {
		return opts.TemplateURL
	}
	cfg := loadFoundConfig()
	return cfg.TemplateURL
}

func runUpdateTemplates(opts *Options) error {
	useColor := isTTY(os.Stdout) && !opts.NoColor
	if useColor {
		logs.Log.SetColor(true)
	}
	if !opts.Quiet {
		logs.Log.Console(banner)
	}

	templateURL := resolveTemplateURL(opts)
	if templateURL == "" {
		return fmt.Errorf("no template repository URL configured\n  use: found --update-templates --template-url <git-repo-url>")
	}

	templateDir := resolveTemplateDir(opts)

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is required for template management: %v", err)
	}

	cfg := loadFoundConfig()
	changed := false
	if opts.TemplateURL != "" && cfg.TemplateURL != opts.TemplateURL {
		cfg.TemplateURL = opts.TemplateURL
		changed = true
	}
	if opts.UpdateTemplateDir != "" && cfg.TemplateDir != opts.UpdateTemplateDir {
		cfg.TemplateDir = opts.UpdateTemplateDir
		changed = true
	}
	if changed {
		if err := saveFoundConfig(cfg); err != nil {
			logs.Log.Warnf("failed to save config: %v", err)
		}
	}

	if isGitRepo(templateDir) {
		return gitPull(templateDir, opts.Quiet)
	}
	return gitClone(templateURL, templateDir, opts.Quiet)
}

func isGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func gitClone(url, dir string, quiet bool) error {
	logs.Log.Infof("Cloning templates from %s", url)
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return fmt.Errorf("create directory: %v", err)
	}
	args := []string{"clone", "--depth", "1", url, dir}
	cmd := exec.Command("git", args...)
	if !quiet {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %v", err)
	}

	count := countTemplateFiles(dir)
	logs.Log.Infof("Templates installed to %s (%d templates)", dir, count)
	return nil
}

func gitPull(dir string, quiet bool) error {
	logs.Log.Infof("Updating templates in %s", dir)
	cmd := exec.Command("git", "-C", dir, "pull", "--ff-only")
	if !quiet {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git pull failed: %v", err)
	}

	count := countTemplateFiles(dir)
	logs.Log.Infof("Templates updated (%d templates)", count)
	return nil
}

func countTemplateFiles(dir string) int {
	count := 0
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			count++
		}
		return nil
	})
	return count
}

// loadLocalTemplates loads templates from the local template directory.
// It tries category subdirectories first; if none match, walks the entire directory.
// Returns true if any templates were loaded.
func loadLocalTemplates(tmpls *[]*templates.Template, tmplDir string, categories []string, execOpts *protocols.ExecuterOptions) bool {
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return false
	}

	var loaded bool
	for _, cat := range categories {
		catDir := filepath.Join(tmplDir, cat)
		if info, err := os.Stat(catDir); err == nil && info.IsDir() {
			ts, _ := loadFromPath(catDir, execOpts)
			*tmpls = append(*tmpls, ts...)
			loaded = true
		}
	}

	if !loaded {
		ts, _ := loadFromPath(tmplDir, execOpts)
		if len(ts) > 0 {
			*tmpls = append(*tmpls, ts...)
			loaded = true
		}
	}

	return loaded
}

// listLocalTemplateInfos returns template info from the local template directory.
func listLocalTemplateInfos(tmplDir string) []templateInfo {
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return nil
	}

	var infos []templateInfo
	filepath.Walk(tmplDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		if ti := getTemplateInfoFromFile(p); ti != nil {
			infos = append(infos, *ti)
		}
		return nil
	})
	return infos
}
