package pennyconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Script represents a user-defined BYOS script entry from penny.yaml
type Script struct {
	Name string `yaml:"name"`
	Tag  string `yaml:"tag"`  // optional slug, e.g. "my-check"
	Path string `yaml:"path"`
}

// Config holds the parsed ~/.penny/penny.yaml config
type Config struct {
	Landing string   `yaml:"landing"`          // e.g. "issues", "byos:my-check", defaults to "system"
	Theme   string   `yaml:"theme"`            // "dark" or "light" (default: "light")
	DebugKI bool     `yaml:"debug_ki,omitempty"` // enable debug output for all ki-scripts globally
	Byos    []Script `yaml:"byos"`
}

// Result holds the output of a single BYOS script execution
type Result struct {
	Name   string `json:"name"`
	Tag    string `json:"tag,omitempty"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// ConfigPath returns the path to ~/.penny/penny.yaml
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".penny", "penny.yaml")
}

// Load reads ~/.penny/penny.yaml and returns the config.
// Returns nil, nil if the file does not exist (config is optional).
func Load() (*Config, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pennyconfig: reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("pennyconfig: parsing config: %w", err)
	}
	return &cfg, nil
}

// expandPath resolves env vars ($HOME, $USER, etc.) and ~ in a path.
func expandPath(path string) string {
	expanded := os.ExpandEnv(path)
	if strings.HasPrefix(expanded, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			expanded = filepath.Join(home, expanded[2:])
		}
	}
	return expanded
}

// ScriptStatus holds filesystem check results for a script (no execution).
type ScriptStatus struct {
	Found      bool `json:"found"`
	Executable bool `json:"executable"`
}

// CheckScript verifies whether a script exists and is executable without running it.
func CheckScript(script Script) ScriptStatus {
	path := expandPath(script.Path)
	info, err := os.Stat(path)
	if err != nil {
		return ScriptStatus{}
	}
	return ScriptStatus{Found: true, Executable: info.Mode()&0111 != 0}
}

// Save marshals cfg and writes it to ~/.penny/penny.yaml, creating the directory if needed.
func Save(cfg *Config) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("pennyconfig: creating .penny dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("pennyconfig: marshalling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("pennyconfig: writing config: %w", err)
	}
	return nil
}

// RunScript executes a single script with the archive directory as $1.
func RunScript(script Script, archiveDir string) Result {
	path := expandPath(script.Path)

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Result{Name: script.Name, Tag: script.Tag, Error: fmt.Sprintf("script not found: %s", path)}
	}
	if err != nil {
		return Result{Name: script.Name, Tag: script.Tag, Error: fmt.Sprintf("cannot stat script: %v", err)}
	}
	if info.Mode()&0111 == 0 {
		return Result{Name: script.Name, Tag: script.Tag, Error: fmt.Sprintf("script is not executable: %s", path)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, archiveDir)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return Result{Name: script.Name, Tag: script.Tag, Output: string(out), Error: "script timed out after 60s"}
	}
	if err != nil {
		return Result{Name: script.Name, Tag: script.Tag, Output: string(out), Error: fmt.Sprintf("script exited with error: %v", err)}
	}
	return Result{Name: script.Name, Tag: script.Tag, Output: string(out)}
}

// RunAll executes all BYOS scripts in cfg. First script with a given tag wins;
// subsequent duplicates are silently skipped. Returns nil if cfg has no scripts.
func RunAll(cfg *Config, archiveDir string) []Result {
	if cfg == nil || len(cfg.Byos) == 0 {
		return nil
	}

	seenTags := make(map[string]bool)
	results := make([]Result, 0, len(cfg.Byos))
	for _, s := range cfg.Byos {
		if s.Tag != "" {
			if seenTags[s.Tag] {
				continue
			}
			seenTags[s.Tag] = true
		}
		results = append(results, RunScript(s, archiveDir))
	}
	return results
}

// KnownIssueSpec is a known issue entry from known_issues.yaml in the TSE toolkit.
type KnownIssueSpec struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
	Title    string `yaml:"title"`
	Script   string `yaml:"script"` // path relative to toolkit root
	URL      string `yaml:"url,omitempty"`
	Debug    string `yaml:"debug,omitempty"` // "on" to print script output to stdout
}

// KnownIssueResult is a matched known issue with details extracted by the script.
type KnownIssueResult struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Workaround  string `json:"workaround,omitempty"`
	URL         string `json:"url,omitempty"`
}

// scriptOutput is the JSON structure a known issue script must print to stdout.
type scriptOutput struct {
	Match       bool   `json:"match"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Workaround  string `json:"workaround,omitempty"`
	Severity    string `json:"severity,omitempty"`
	URL         string `json:"url,omitempty"`
}

func kiCheckCandidate(prefix, suffix string) string {
	candidate := filepath.Join(prefix, suffix)
	if _, err := os.Stat(filepath.Join(candidate, "known_issues.yaml")); err == nil {
		return candidate
	}
	return ""
}

// FindKnownIssuesRoot returns the directory containing known_issues.yaml and ki-scripts.
// Priority: $HOME/.penny first, then TSE_ToolKit entries in $PATH, then cloud storage roots.
func FindKnownIssuesRoot() (string, error) {
	home, _ := os.UserHomeDir()

	if home != "" {
		candidate := filepath.Join(home, ".penny")
		if _, err := os.Stat(filepath.Join(candidate, "known_issues.yaml")); err == nil {
			return candidate, nil
		}
	}

	pathEnv := os.Getenv("PATH")
	for _, dir := range strings.Split(pathEnv, ":") {
		dir = strings.TrimRight(dir, "/")
		if !strings.HasSuffix(dir, "Scripts/TSE_ToolKit") {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, ".penny", "known_issues.yaml")); err == nil {
			return filepath.Join(dir, ".penny"), nil
		}
	}

	// Fall back to scanning cloud storage roots (OneDrive, Dropbox variants) for TSE_ToolKit installs
	// that aren't on $PATH. Each root is globbed one level deep, then the fixed toolkit suffix appended.
	if home != "" {
		toolkitSuffix := filepath.Join("Technical Support", "Technical Resources", "Scripts", "TSE_ToolKit", ".penny")
		cloudRoots := []string{
			filepath.Join(home, "Library", "CloudStorage"), // macOS OneDrive/SharePoint
		}
		// Also cover Dropbox roots directly under $HOME (e.g. "Dropbox (Nozomi Networks)", "Nozomi Networks Dropbox")
		if entries, err := os.ReadDir(home); err == nil {
			for _, e := range entries {
				if e.IsDir() && (strings.Contains(e.Name(), "Dropbox") || strings.Contains(e.Name(), "Box")) {
					cloudRoots = append(cloudRoots, filepath.Join(home, e.Name()))
				}
			}
		}
		for _, root := range cloudRoots {
			// Search up to three levels deep under each cloud root to handle layouts like:
			// CloudStorage/<provider>/<folder>/<subfolder>/Technical Support/...
			top, _ := os.ReadDir(root)
			for _, e1 := range top {
				p1 := filepath.Join(root, e1.Name())
				if found := kiCheckCandidate(p1, toolkitSuffix); found != "" {
					return found, nil
				}
				mid, _ := os.ReadDir(p1)
				for _, e2 := range mid {
					p2 := filepath.Join(p1, e2.Name())
					if found := kiCheckCandidate(p2, toolkitSuffix); found != "" {
						return found, nil
					}
					deep, _ := os.ReadDir(p2)
					for _, e3 := range deep {
						p3 := filepath.Join(p2, e3.Name())
						if found := kiCheckCandidate(p3, toolkitSuffix); found != "" {
							return found, nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("known_issues.yaml not found in $HOME/.penny, TSE_ToolKit in $PATH, or cloud storage")
}

// LoadKnownIssues reads known_issues.yaml from the given root directory.
// Returns an empty slice (no error) if the file does not exist.
func LoadKnownIssues(root string) ([]KnownIssueSpec, error) {
	path := filepath.Join(root, "known_issues.yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pennyconfig: reading known_issues.yaml: %w", err)
	}
	var specs []KnownIssueSpec
	if err := yaml.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("pennyconfig: parsing known_issues.yaml: %w", err)
	}
	return specs, nil
}

// RunKnownIssue executes a single known issue script, piping archiveJSON to stdin
// and archiveDir as $1. Returns nil if the script reports no match.
func RunKnownIssue(spec KnownIssueSpec, root string, archiveJSON []byte, archiveDir string, globalDebug bool) (*KnownIssueResult, error) {
	scriptPath := filepath.Join(root, spec.Script)
	info, err := os.Stat(scriptPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("script not found: %s", scriptPath)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot stat script %s: %w", scriptPath, err)
	}
	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("script not executable: %s", scriptPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, scriptPath, archiveDir)
	cmd.Stdin = bytes.NewReader(archiveJSON)
	out, err := cmd.Output()
	if globalDebug || spec.Debug == "on" {
		fmt.Printf("\n[debug %s] %s\n", spec.ID, string(out))
	}
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("script %s timed out after 60s", spec.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("script %s failed: %w", spec.ID, err)
	}

	var result scriptOutput
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return nil, fmt.Errorf("script %s produced invalid JSON: %w", spec.ID, err)
	}
	if !result.Match {
		return nil, nil
	}

	// Merge script output over YAML defaults
	r := &KnownIssueResult{
		ID:          spec.ID,
		Severity:    spec.Severity,
		Title:       spec.Title,
		URL:         spec.URL,
		Description: result.Description,
		Workaround:  result.Workaround,
	}
	if result.Title != "" {
		r.Title = result.Title
	}
	if result.Severity != "" {
		r.Severity = result.Severity
	}
	if result.URL != "" {
		r.URL = result.URL
	}
	return r, nil
}
