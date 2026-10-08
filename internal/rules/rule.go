// Package rules defines sweep's classification rules: what a path is, which
// category it belongs to, and how risky deleting it would be.
//
// Rules are data (embedded YAML in builtin/, plus optional user rules), so
// new ones need no code changes. They can only describe; the safety package
// has the final say on what may be deleted, and nothing here can override it.
package rules

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mishraprayash/macsweep/internal/safety"
)

// Rule is one classification rule.
type Rule struct {
	ID             string      `yaml:"id" json:"id"`
	Category       string      `yaml:"category" json:"category"`
	Match          Match       `yaml:"match" json:"match"`
	Tier           safety.Tier `yaml:"tier" json:"tier"`
	Description    string      `yaml:"description" json:"description"`
	RegenerateHint string      `yaml:"regenerate_hint" json:"regenerate_hint,omitempty"`
	// StaleAfterDays flags project artifacts whose project has had no
	// activity for this many days.
	StaleAfterDays int `yaml:"stale_after_days" json:"stale_after_days,omitempty"`
	// NativeClean is a command to prefer over deleting files, e.g.
	// ["go", "clean", "-cache"]. Only built-in rules may set it.
	NativeClean []string `yaml:"native_clean" json:"native_clean,omitempty"`
	// NativeOnly means the files must never be deleted directly; only
	// NativeClean may reclaim the space (e.g. Docker.raw).
	NativeOnly bool `yaml:"native_only" json:"native_only,omitempty"`
	// CleanContents means clean empties the directory rather than removing it
	// (e.g. ~/.Trash).
	CleanContents bool `yaml:"clean_contents" json:"clean_contents,omitempty"`

	// Synthetic rules are not matched by their match block, which only
	// documents where they apply; built-in detectors decide instead, because
	// they need to know which version is in use (old Homebrew versions in the
	// classifier, version stores such as nvm's in versions.go).
	Synthetic bool `yaml:"synthetic" json:"synthetic,omitempty"`

	// Source is where the rule was defined, e.g. "builtin/node.yaml".
	Source string `yaml:"-" json:"source"`
	// User is true for rules from the user's config file.
	User bool `yaml:"-" json:"user"`
}

// Match selects paths. Exactly one selector (path, glob, name/dir_name, or
// ext) must be set; the rest are additional conditions.
type Match struct {
	// Path is one or more exact paths ("~" is expanded).
	Path StringList `yaml:"path" json:"path,omitempty"`
	// Glob is one or more path patterns. "*" matches within one path
	// component and "**" matches any number of components.
	Glob StringList `yaml:"glob" json:"glob,omitempty"`
	// Name matches the final path component (glob patterns allowed).
	Name StringList `yaml:"name" json:"name,omitempty"`
	// DirName is Name restricted to directories.
	DirName StringList `yaml:"dir_name" json:"dir_name,omitempty"`
	// Ext matches file extensions, e.g. [".dmg", ".iso"].
	Ext StringList `yaml:"ext" json:"ext,omitempty"`

	// Type restricts to "dir" or "file". Default: dir for dir_name, file for
	// ext, either otherwise.
	Type string `yaml:"type" json:"type,omitempty"`
	// Under restricts matches to paths below this directory ("~" expanded).
	Under string `yaml:"under" json:"under,omitempty"`
	// RequireSiblingAny: at least one of these names must exist next to the
	// match (e.g. node_modules only with a package.json beside it).
	RequireSiblingAny []string `yaml:"require_sibling_any" json:"require_sibling_any,omitempty"`
	// RequireParentMarker: at least one of these names must exist in one of
	// the match's ancestor directories (up to markerDepth levels up).
	RequireParentMarker []string `yaml:"require_parent_marker" json:"require_parent_marker,omitempty"`
	// RequireChildAny: at least one of these names must exist inside the
	// matched directory (e.g. .venv only with pyvenv.cfg inside).
	RequireChildAny []string `yaml:"require_child_any" json:"require_child_any,omitempty"`
	// MinSize and MinAgeDays filter by size and by age of the newest content.
	MinSize    Size `yaml:"min_size" json:"min_size,omitempty"`
	MinAgeDays int  `yaml:"min_age_days" json:"min_age_days,omitempty"`
	// UserFiles restricts matches to the user's own visible folders: under
	// home, outside ~/Library, and with no hidden folder in the path (apps
	// and tools keep large internal files there that are not "your" files).
	UserFiles bool `yaml:"user_files" json:"user_files,omitempty"`
	// Project marks a per-project build artifact. Such matches only count
	// inside the user's own workspace (see Set.Match) and get staleness.
	Project bool `yaml:"project" json:"project,omitempty"`
}

// StringList accepts either a single string or a list in YAML.
type StringList []string

func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = StringList{n.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := n.Decode(&l); err != nil {
			return err
		}
		*s = l
		return nil
	default:
		return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
	}
}

// Size is a byte count written as "500MB", "2GB", "10KiB", or a plain number.
// Decimal units are base-10, matching Finder.
type Size uint64

var sizeRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([A-Za-z]*)$`)

var sizeUnits = map[string]float64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

// ParseSize parses a human size such as "500MB".
func ParseSize(s string) (Size, error) {
	m := sizeRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (want e.g. 500MB, 2GB)", s)
	}
	unit, ok := sizeUnits[strings.ToLower(m[2])]
	if !ok {
		return 0, fmt.Errorf("invalid size unit in %q (use B, KB, MB, GB, TB or KiB, MiB, GiB, TiB)", s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	return Size(v * unit), nil
}

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*s = v
	return nil
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// selector returns which selector the rule uses, or an error if not exactly one.
func (m *Match) selector() (string, error) {
	var set []string
	if len(m.Path) > 0 {
		set = append(set, "path")
	}
	if len(m.Glob) > 0 {
		set = append(set, "glob")
	}
	if len(m.Name) > 0 {
		set = append(set, "name")
	}
	if len(m.DirName) > 0 {
		set = append(set, "dir_name")
	}
	if len(m.Ext) > 0 {
		set = append(set, "ext")
	}
	switch len(set) {
	case 0:
		return "", errors.New("match needs one of path, glob, name, dir_name, or ext")
	case 1:
		return set[0], nil
	default:
		return "", fmt.Errorf("match sets %s; use exactly one selector per rule", strings.Join(set, " and "))
	}
}

// validate checks a rule in isolation. Errors name the rule and field.
func (r *Rule) validate() error {
	fail := func(format string, args ...any) error {
		id := r.ID
		if id == "" {
			id = "(missing id)"
		}
		return fmt.Errorf("%s: rule %s: %s", r.Source, id, fmt.Sprintf(format, args...))
	}
	if !idRE.MatchString(r.ID) {
		return fail("id must be lowercase letters, digits and dashes")
	}
	if strings.TrimSpace(r.Category) == "" {
		return fail("category is required")
	}
	if r.Tier == safety.TierUnknown {
		return fail("tier is required (SAFE, CAUTION, REVIEW, or PROTECTED)")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fail("description is required")
	}
	sel, err := r.Match.selector()
	if err != nil {
		return fail("%v", err)
	}
	m := &r.Match
	switch m.Type {
	case "", "dir", "file":
	default:
		return fail("type must be dir or file, got %q", m.Type)
	}
	if sel == "dir_name" && m.Type == "file" {
		return fail("dir_name cannot be combined with type: file")
	}
	if sel == "ext" && m.Type == "dir" {
		return fail("ext cannot be combined with type: dir")
	}
	for _, p := range m.Path {
		if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") {
			return fail("path %q must be absolute or start with ~/", p)
		}
		if p != filepath.Clean(p) {
			return fail("path %q is not clean (want %q)", p, filepath.Clean(p))
		}
	}
	for _, g := range m.Glob {
		if err := validateGlob(g); err != nil {
			return fail("%v", err)
		}
	}
	for _, n := range append(append([]string{}, m.Name...), m.DirName...) {
		if n == "" || strings.Contains(n, "/") {
			return fail("name %q must be a single path component", n)
		}
		if _, err := filepath.Match(n, ""); err != nil {
			return fail("name %q: %v", n, err)
		}
	}
	for _, e := range m.Ext {
		if !strings.HasPrefix(e, ".") || len(e) < 2 || strings.Contains(e, "/") {
			return fail("ext %q must look like .dmg", e)
		}
	}
	if m.Under != "" && !strings.HasPrefix(m.Under, "/") && m.Under != "~" && !strings.HasPrefix(m.Under, "~/") {
		return fail("under %q must be absolute or start with ~", m.Under)
	}
	for _, list := range [][]string{m.RequireSiblingAny, m.RequireParentMarker, m.RequireChildAny} {
		for _, n := range list {
			if n == "" || strings.Contains(n, "/") || n == "." || n == ".." {
				return fail("marker %q must be a single file or directory name", n)
			}
		}
	}
	if len(m.RequireChildAny) > 0 && (m.Type == "file" || sel == "ext") {
		return fail("require_child_any only applies to directories")
	}
	if m.MinAgeDays < 0 || r.StaleAfterDays < 0 {
		return fail("min_age_days and stale_after_days must not be negative")
	}
	if r.StaleAfterDays > 0 && !m.Project {
		return fail("stale_after_days requires project: true")
	}
	if r.NativeOnly && len(r.NativeClean) == 0 {
		return fail("native_only requires native_clean")
	}
	if len(r.NativeClean) > 0 && !allowedNative[r.NativeClean[0]] {
		return fail("native_clean command %q is not in the allowed list", r.NativeClean[0])
	}
	if r.User && r.Synthetic {
		return fail("user rules cannot be synthetic")
	}
	if r.User && (len(r.NativeClean) > 0 || r.NativeOnly) {
		return fail("user rules cannot run commands (native_clean); only built-in rules can")
	}
	return nil
}

// allowedNative is the set of programs built-in rules may name in
// native_clean. The cleaner re-checks this before running anything.
var allowedNative = map[string]bool{
	"go": true, "brew": true, "docker": true, "xcrun": true, "tmutil": true,
	"npm": true, "pnpm": true, "yarn": true, "conda": true,
}

// AllowedNative reports whether cmd may be used in native_clean.
func AllowedNative(cmd string) bool { return allowedNative[cmd] }
