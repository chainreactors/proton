package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/proton/pkg"
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/template"
	"gopkg.in/yaml.v3"
)

// TemplateInfo holds basic metadata about a template.
type TemplateInfo struct {
	ID       string
	Name     string
	Severity string
}

// LoadTemplates loads templates according to the provided Config.
func LoadTemplates(cfg *Config) ([]*template.Template, error) {
	execOpts := &protocols.ExecuterOptions{
		Options: &protocols.Options{TextOnly: !cfg.Bin},
	}

	excludePaths := make(map[string]bool)
	for _, p := range cfg.ExcludeTemplates {
		abs, err := filepath.Abs(p)
		if err == nil {
			excludePaths[abs] = true
		}
	}

	var tmpls []*template.Template

	loadFiltered := func(path string) error {
		loaded, err := LoadFromPath(path, execOpts)
		if err != nil {
			return err
		}
		for _, t := range loaded {
			tmpls = append(tmpls, t)
		}
		return nil
	}

	for _, tmplPath := range cfg.Templates {
		if abs, err := filepath.Abs(tmplPath); err == nil && excludePaths[abs] {
			continue
		}
		if err := loadFiltered(tmplPath); err != nil {
			return nil, fmt.Errorf("loading template %s: %v", tmplPath, err)
		}
	}

	if len(cfg.Templates) == 0 {
		tmplDir := cfg.TemplateDir
		if loadLocalTemplates(&tmpls, tmplDir, cfg.Categories, execOpts) {
			logs.Log.Debugf("Loaded templates from %s", tmplDir)
		} else if loaded := loadEmbeddedTemplates(&tmpls, cfg.Categories, execOpts); !loaded {
			categoryDirs := categoryTemplateDirs(cfg.TemplateDir, cfg.Categories)
			loadedCategory := false
			for _, catDir := range categoryDirs {
				if _, err := os.Stat(catDir); os.IsNotExist(err) {
					continue
				}
				loadedCategory = true
				if err := loadFiltered(catDir); err != nil {
					return nil, fmt.Errorf("loading template category %s: %v", catDir, err)
				}
			}
			if !loadedCategory {
				return nil, fmt.Errorf("category directory not found: %s (use -t to specify template path)", strings.Join(categoryDirs, ", "))
			}
		}
	}

	tmpls = FilterTemplates(tmpls, cfg)
	return tmpls, nil
}

// LoadFromPath loads templates from a file or directory path.
func LoadFromPath(path string, execOpts *protocols.ExecuterOptions) ([]*template.Template, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		tmpl, err := loadSingleTemplate(path, execOpts)
		if err != nil {
			return nil, err
		}
		return []*template.Template{tmpl}, nil
	}

	var tmpls []*template.Template
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		tmpl, err := loadSingleTemplate(p, execOpts)
		if err != nil {
			return nil
		}
		tmpls = append(tmpls, tmpl)
		return nil
	})
	return tmpls, nil
}

func loadSingleTemplate(path string, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTemplate(path, data, execOpts)
}

// ParseTemplate parses and compiles a single template from raw YAML data.
func ParseTemplate(name string, data []byte, execOpts *protocols.ExecuterOptions) (*template.Template, error) {
	var tmpl template.Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse %s: %v", name, err)
	}
	if len(tmpl.RequestsFile) == 0 && len(tmpl.RequestsSys) == 0 {
		return nil, fmt.Errorf("no file or sys requests in %s", name)
	}
	if err := tmpl.Compile(execOpts); err != nil {
		return nil, fmt.Errorf("compile %s: %v", name, err)
	}
	return &tmpl, nil
}

// FilterTemplates filters templates by tags, IDs, and exclusion rules from config.
func FilterTemplates(tmpls []*template.Template, cfg *Config) []*template.Template {
	includeTags := toSet(cfg.Tags)
	excludeTags := toSet(cfg.ExcludeTags)
	includeIDs := toSet(cfg.TemplateIDs)
	excludeIDs := toSet(cfg.ExcludeIDs)

	if len(includeTags) == 0 && len(excludeTags) == 0 &&
		len(includeIDs) == 0 && len(excludeIDs) == 0 {
		return tmpls
	}

	var filtered []*template.Template
	for _, tmpl := range tmpls {
		if len(excludeIDs) > 0 && excludeIDs[tmpl.Id] {
			continue
		}
		if len(includeIDs) > 0 && !includeIDs[tmpl.Id] {
			continue
		}

		tags := tmpl.GetTags()

		if len(excludeTags) > 0 && matchAnyTag(tags, excludeTags) {
			continue
		}
		if len(includeTags) > 0 && !matchAnyTag(tags, includeTags) {
			continue
		}

		filtered = append(filtered, tmpl)
	}
	return filtered
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[strings.TrimSpace(strings.ToLower(item))] = true
	}
	return s
}

func matchAnyTag(tags []string, set map[string]bool) bool {
	for _, tag := range tags {
		if set[strings.TrimSpace(strings.ToLower(tag))] {
			return true
		}
	}
	return false
}

func buildExpressionRule(expressions []string, extFilter string, execOpts *protocols.ExecuterOptions) (file.Rule, error) {
	req := &file.Request{}

	if extFilter != "" {
		for _, ext := range strings.Split(extFilter, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				req.Extensions = append(req.Extensions, ext)
			}
		}
	} else {
		req.Extensions = []string{"all"}
	}

	var extractors []*operators.Extractor
	for _, expr := range expressions {
		extractors = append(extractors, &operators.Extractor{
			Type:  "regex",
			Regex: []string{expr},
		})
	}
	req.Extractors = extractors

	if err := req.Compile(execOpts); err != nil {
		return file.Rule{}, err
	}

	return file.Rule{
		ID:       "cli-expression",
		Name:     "CLI Expression",
		Severity: "info",
		Requests: []*file.Request{req},
	}, nil
}

func EmbeddedTemplateConfigs(categories []string) []string {
	seen := make(map[string]bool)
	var configs []string
	for _, cat := range canonicalTemplateCategories(categories) {
		name := "found_" + strings.ReplaceAll(cat, "/", "_")
		if seen[name] {
			continue
		}
		seen[name] = true
		configs = append(configs, name)
	}
	return configs
}

func canonicalTemplateCategories(categories []string) []string {
	if len(categories) == 0 {
		categories = []string{"keys"}
	}

	seen := make(map[string]bool)
	var canonical []string
	add := func(cat string) {
		if cat == "" || seen[cat] {
			return
		}
		seen[cat] = true
		canonical = append(canonical, cat)
	}

	for _, cat := range categories {
		cat = strings.ToLower(strings.Trim(strings.TrimSpace(strings.ReplaceAll(cat, `\`, `/`)), `/`))
		switch cat {
		case "":
			continue
		case "all":
			add("keys")
			add("spray")
		case "key", "keys", "found/keys", "found_keys":
			add("keys")
		case "spray", "found/spray", "found_spray":
			add("spray")
		default:
			cat = strings.TrimPrefix(cat, "found/")
			cat = strings.TrimPrefix(cat, "found_")
			add(cat)
		}
	}
	return canonical
}

func appendEmbeddedTemplateInfos(infos *[]TemplateInfo, categories []string) bool {
	loaded := false
	for _, config := range EmbeddedTemplateConfigs(categories) {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if yaml.Unmarshal(data, &pocs) != nil {
			continue
		}
		for _, poc := range pocs {
			bs, _ := yaml.Marshal(poc)
			if ti := getTemplateInfoFromData(bs); ti != nil {
				*infos = append(*infos, *ti)
				loaded = true
			}
		}
	}
	return loaded
}

// loadEmbeddedTemplates loads templates from the embedded pkg.LoadConfig data.
func loadEmbeddedTemplates(tmpls *[]*template.Template, categories []string, execOpts *protocols.ExecuterOptions) bool {
	loaded := false
	for _, config := range EmbeddedTemplateConfigs(categories) {
		data := pkg.LoadConfig(config)
		if len(data) == 0 {
			continue
		}
		var pocs []interface{}
		if err := yaml.Unmarshal(data, &pocs); err != nil {
			continue
		}
		for _, poc := range pocs {
			bs, err := yaml.Marshal(poc)
			if err != nil {
				continue
			}
			tmpl, err := ParseTemplate("embedded:"+config, bs, execOpts)
			if err != nil {
				continue
			}
			*tmpls = append(*tmpls, tmpl)
			loaded = true
		}
	}
	return loaded
}

// loadLocalTemplates loads templates from found category directories in the local template directory.
// Returns true if any templates were loaded.
func loadLocalTemplates(tmpls *[]*template.Template, tmplDir string, categories []string, execOpts *protocols.ExecuterOptions) bool {
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return false
	}

	var loaded bool
	for _, catDir := range categoryTemplateDirs(tmplDir, categories) {
		if info, err := os.Stat(catDir); err == nil && info.IsDir() {
			ts, _ := LoadFromPath(catDir, execOpts)
			*tmpls = append(*tmpls, ts...)
			loaded = true
		}
	}

	return loaded
}

// listLocalTemplateInfos returns template info from the local template directory.
func listLocalTemplateInfos(tmplDir string) []TemplateInfo {
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return nil
	}

	var infos []TemplateInfo
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

// LoadFiltersFromEmbedded loads extension and directory filters from embedded
// templates and applies them to the proton file scanner.
func LoadFiltersFromEmbedded() {
	cfg := file.FilterConfig{}

	if extData := pkg.LoadConfig("found_filter_ext"); len(extData) > 0 {
		var extGroups map[string][]string
		if yaml.Unmarshal(extData, &extGroups) == nil {
			cfg.AlwaysDenyExts = toExtSet(extGroups["always"])
			cfg.ExecDenyExts = toExtSet(extGroups["executable"])
			cfg.ArchiveDenyExts = toExtSet(extGroups["archive"])
			cfg.DocDenyExts = toExtSet(extGroups["document"])
			cfg.MiscDenyExts = toExtSet(extGroups["misc"])
		}
	}

	if dirData := pkg.LoadConfig("found_filter_dir"); len(dirData) > 0 {
		var dirGroups map[string][]string
		if yaml.Unmarshal(dirData, &dirGroups) == nil {
			cfg.SkipDirs = toExtSet(dirGroups["skip"])
		}
	}

	file.SetFilters(cfg)
}

func toExtSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

func getTemplateInfoFromFile(path string) *TemplateInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return getTemplateInfoFromData(data)
}

func getTemplateInfoFromData(data []byte) *TemplateInfo {
	var tmpl template.Template
	if yaml.Unmarshal(data, &tmpl) != nil {
		return nil
	}
	if len(tmpl.RequestsFile) == 0 && len(tmpl.RequestsSys) == 0 {
		return nil
	}
	sev := tmpl.Info.Severity
	if sev == "" {
		sev = "unknown"
	}
	return &TemplateInfo{ID: tmpl.Id, Name: tmpl.Info.Name, Severity: sev}
}

// ListTemplates collects template info from local dirs, explicit paths, and embedded templates.
func ListTemplates(tmplDir string, templatePaths []string, categories []string) []TemplateInfo {
	var infos []TemplateInfo

	if len(templatePaths) > 0 {
		for _, path := range templatePaths {
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if !info.IsDir() {
				if ti := getTemplateInfoFromFile(path); ti != nil {
					infos = append(infos, *ti)
				}
				continue
			}
			filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
					return nil
				}
				if ti := getTemplateInfoFromFile(p); ti != nil {
					infos = append(infos, *ti)
				}
				return nil
			})
		}
	} else if localInfos := listLocalTemplateInfos(tmplDir); len(localInfos) > 0 {
		infos = localInfos
	} else if appendEmbeddedTemplateInfos(&infos, categories) {
	} else {
		for _, catDir := range categoryTemplateDirs(tmplDir, categories) {
			filepath.Walk(catDir, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
					return nil
				}
				if ti := getTemplateInfoFromFile(p); ti != nil {
					infos = append(infos, *ti)
				}
				return nil
			})
		}
	}
	return infos
}

func categoryTemplateDirs(tmplDir string, categories []string) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, cat := range canonicalTemplateCategories(categories) {
		dir := filepath.Join(tmplDir, filepath.FromSlash("found/"+cat))
		if seen[dir] {
			continue
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	return dirs
}
