package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// markerDepth bounds how far up require_parent_marker looks.
	markerDepth = 4
	// projectSearchDepth bounds how far up project-root detection looks for
	// rules without an explicit marker.
	projectSearchDepth = 6
)

// projectMarkers identify a project root for artifacts without their own
// marker (e.g. __pycache__).
var projectMarkers = []string{
	".git", "package.json", "Cargo.toml", "go.mod", "pyproject.toml", "setup.py",
	"requirements.txt", "Pipfile", "Podfile", "build.gradle", "build.gradle.kts",
	"pom.xml", "Package.swift", "Gemfile", "composer.json", "mix.exs",
}

// Candidate is a path to classify.
type Candidate struct {
	Path  string
	IsDir bool
	Size  uint64    // files only; unknown (0) for directories
	MTime time.Time // files: mtime; directories: unused
}

// Result is a successful match.
type Result struct {
	Rule *Rule
	// Reason explains, in words, why the rule matched.
	Reason string
	// ProjectRoot is set for project artifacts.
	ProjectRoot string
	// Deferred means min_size/min_age could not be checked yet (directory
	// sizes are only known after the scan) and must be checked by the caller.
	Deferred bool
}

// Set is a compiled, validated collection of rules plus user exclusions.
type Set struct {
	home     string
	homeComp []string
	now      func() time.Time
	getenv   func(string) string
	all      []*compiled
	byID     map[string]*compiled
	exact    map[string][]exactRule // keyed by lowercased base name
	names    map[string][]*compiled
	namePats []*compiled
	exts     map[string][]*compiled
	globs    []*compiled
	excludes []pathGlob
	stores   []storeDir
}

type exactRule struct {
	path string // clean, absolute
	c    *compiled
}

// namePattern matches a lowercased base name. Patterns of the common forms
// "*.ext" and "prefix*" are checked with string functions, not filepath.Match,
// because Match runs on every scanned entry.
type namePattern struct {
	glob           string
	suffix, prefix string
	simple         bool
}

func newNamePattern(p string) namePattern {
	rest := p[1:]
	if strings.HasPrefix(p, "*") && !strings.ContainsAny(rest, `*?[\`) {
		return namePattern{glob: p, suffix: rest, simple: true}
	}
	head := strings.TrimSuffix(p, "*")
	if strings.HasSuffix(p, "*") && !strings.ContainsAny(head, `*?[\`) {
		return namePattern{glob: p, prefix: head, simple: true}
	}
	return namePattern{glob: p}
}

func (n namePattern) match(name string) bool {
	if n.simple {
		return strings.HasSuffix(name, n.suffix) && strings.HasPrefix(name, n.prefix)
	}
	ok, _ := filepath.Match(n.glob, name)
	return ok
}

type compiled struct {
	*Rule
	order    int
	selector string
	globs    []pathGlob
	namePats []namePattern
	under    []string
	typ      string
}

// Options configures NewSet.
type Options struct {
	Home     string
	Rules    []*Rule
	Excludes []string
	// Now is the clock for min_age_days. Defaults to time.Now.
	Now func() time.Time
	// Getenv reads the environment (e.g. $NVM_BIN). Defaults to os.Getenv.
	Getenv func(string) string
}

// NewSet validates and compiles rules. It reports every problem at once.
func NewSet(o Options) (*Set, error) {
	if o.Home == "" || !filepath.IsAbs(o.Home) {
		return nil, fmt.Errorf("rules: home must be absolute, got %q", o.Home)
	}
	s := &Set{
		home:     filepath.Clean(o.Home),
		homeComp: splitLower(o.Home),
		now:      o.Now,
		getenv:   o.Getenv,
		byID:     map[string]*compiled{},
		exact:    map[string][]exactRule{},
		names:    map[string][]*compiled{},
		exts:     map[string][]*compiled{},
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.getenv == nil {
		s.getenv = os.Getenv
	}
	var errs []error
	for i, r := range o.Rules {
		if err := r.validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, dup := s.byID[r.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: rule %s: id already defined in %s", r.Source, r.ID, prev.Source))
			continue
		}
		c := &compiled{Rule: r, order: i}
		if !r.Synthetic {
			c = s.compile(r, i)
		}
		s.all = append(s.all, c)
		s.byID[r.ID] = c
	}
	for _, e := range o.Excludes {
		if err := validateGlob(e); err != nil {
			errs = append(errs, fmt.Errorf("exclude: %w", err))
			continue
		}
		s.excludes = append(s.excludes, compileGlob(s.expand(e)))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	s.compileStores()
	return s, nil
}

func (s *Set) expand(p string) string {
	if p == "~" {
		return s.home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(s.home, rest)
	}
	return p
}

func (s *Set) compile(r *Rule, order int) *compiled {
	m := &r.Match
	sel, _ := m.selector()
	c := &compiled{Rule: r, order: order, selector: sel, typ: m.Type}
	if m.Under != "" {
		c.under = splitLower(s.expand(m.Under))
	}
	switch sel {
	case "path":
		for _, p := range m.Path {
			abs := filepath.Clean(s.expand(p))
			k := strings.ToLower(filepath.Base(abs))
			s.exact[k] = append(s.exact[k], exactRule{path: abs, c: c})
		}
	case "glob":
		for _, g := range m.Glob {
			c.globs = append(c.globs, compileGlob(s.expand(g)))
		}
		s.globs = append(s.globs, c)
	case "name", "dir_name":
		if sel == "dir_name" {
			c.typ = "dir"
		}
		names := m.Name
		if sel == "dir_name" {
			names = m.DirName
		}
		for _, n := range names {
			ln := strings.ToLower(n)
			if strings.ContainsAny(ln, `*?[\`) {
				c.namePats = append(c.namePats, newNamePattern(ln))
			} else {
				s.names[ln] = append(s.names[ln], c)
			}
		}
		if len(c.namePats) > 0 {
			s.namePats = append(s.namePats, c)
		}
	case "ext":
		if c.typ == "" {
			c.typ = "file"
		}
		for _, e := range m.Ext {
			le := strings.ToLower(e)
			s.exts[le] = append(s.exts[le], c)
		}
	}
	return c
}

// Rules returns all rules sorted by category, then id.
func (s *Set) Rules() []*Rule {
	out := make([]*Rule, 0, len(s.all))
	for _, c := range s.all {
		out = append(out, c.Rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ByID returns the rule with the given id.
func (s *Set) ByID(id string) (*Rule, bool) {
	c, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return c.Rule, true
}

// Home returns the home directory rules were compiled against.
func (s *Set) Home() string { return s.home }

// priority orders competing matches: the most specific selector wins; ties go
// to the stricter tier, then to the rule defined first.
func (c *compiled) priority(lit int) int {
	switch c.selector {
	case "path":
		return 4000
	case "glob":
		return 3000 + lit*10
	case "name", "dir_name":
		if len(c.namePats) > 0 {
			return 1500
		}
		return 2000
	default: // ext
		return 1000
	}
}

type candidateRule struct {
	c   *compiled
	pri int
}

// Match returns the best rule for cand. Size and age conditions are checked
// for files; for directories they are deferred to the caller (see
// Result.Deferred and CheckDeferred).
func (s *Set) Match(cand Candidate) (Result, bool) {
	// Called for every scanned entry: keep the no-match path cheap. Only
	// the base name is lowercased up front; the full path is split only if
	// a path pattern's quick check passes.
	path := cand.Path
	if !isClean(path) {
		path = filepath.Clean(path)
	}
	if len(path) < 2 || path[0] != '/' {
		return Result{}, false
	}
	if len(s.stores) > 0 {
		if res, ok, isStore := s.matchVersion(path); isStore {
			return res, ok
		}
	}
	name := strings.ToLower(path[strings.LastIndexByte(path, '/')+1:])

	var cands []candidateRule
	add := func(c *compiled, lit int) { cands = append(cands, candidateRule{c, c.priority(lit)}) }
	for _, e := range s.exact[name] {
		if strings.EqualFold(path, e.path) {
			add(e.c, 0)
		}
	}
	for _, c := range s.names[name] {
		add(c, 0)
	}
	for _, c := range s.namePats {
		for _, p := range c.namePats {
			if p.match(name) {
				add(c, 0)
				break
			}
		}
	}
	if !cand.IsDir {
		if ext := filepath.Ext(name); ext != "" {
			for _, c := range s.exts[ext] {
				add(c, 0)
			}
		}
	}
	var comps []string
	for _, c := range s.globs {
		for _, g := range c.globs {
			if !g.quick(path) {
				continue
			}
			if comps == nil {
				comps = splitLower(path)
			}
			if g.match(comps) {
				add(c, g.literal)
				break
			}
		}
	}
	if len(cands) == 0 {
		return Result{}, false
	}
	if comps == nil {
		comps = splitLower(path)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.pri != b.pri {
			return a.pri > b.pri
		}
		if a.c.Tier != b.c.Tier {
			return a.c.Tier > b.c.Tier
		}
		return a.c.order < b.c.order
	})
	for _, cr := range cands {
		if res, ok := s.check(cr.c, path, comps, cand); ok {
			return res, true
		}
	}
	return Result{}, false
}

// check applies a candidate rule's conditions beyond its selector.
func (s *Set) check(c *compiled, path string, comps []string, cand Candidate) (Result, bool) {
	m := &c.Match
	switch c.typ {
	case "dir":
		if !cand.IsDir {
			return Result{}, false
		}
	case "file":
		if cand.IsDir {
			return Result{}, false
		}
	}
	if c.under != nil && !hasPrefix(comps, c.under, true) {
		return Result{}, false
	}
	if (m.Project || m.UserFiles) && !s.inWorkspace(comps) {
		return Result{}, false
	}

	reasons := []string{s.selectorReason(c, path)}
	res := Result{Rule: c.Rule}
	dir := filepath.Dir(path)

	if len(m.RequireSiblingAny) > 0 {
		found, ok := anyExists(dir, m.RequireSiblingAny)
		if !ok {
			return Result{}, false
		}
		reasons = append(reasons, found+" next to it")
		if m.Project {
			res.ProjectRoot = dir
		}
	}
	if len(m.RequireParentMarker) > 0 {
		root, found, ok := s.findUp(dir, m.RequireParentMarker, markerDepth)
		if !ok {
			return Result{}, false
		}
		reasons = append(reasons, fmt.Sprintf("%s in enclosing %s", found, root))
		if m.Project {
			res.ProjectRoot = root
		}
	}
	if len(m.RequireChildAny) > 0 {
		found, ok := anyExists(path, m.RequireChildAny)
		if !ok {
			return Result{}, false
		}
		reasons = append(reasons, found+" inside")
	}
	if m.Project && res.ProjectRoot == "" {
		if root, _, ok := s.findUp(dir, projectMarkers, projectSearchDepth); ok {
			res.ProjectRoot = root
		} else {
			res.ProjectRoot = dir
		}
	}

	if cand.IsDir {
		res.Deferred = m.MinSize > 0 || m.MinAgeDays > 0
	} else {
		if !s.SizeAgeOK(c.Rule, cand.Size, cand.MTime) {
			return Result{}, false
		}
		reasons = append(reasons, s.sizeAgeReason(c.Rule)...)
	}
	res.Reason = strings.Join(reasons, "; ")
	return res, true
}

// SizeAgeOK checks a rule's min_size and min_age_days against a size and the
// newest modification time of the content.
func (s *Set) SizeAgeOK(r *Rule, size uint64, newest time.Time) bool {
	if r.Match.MinSize > 0 && size < uint64(r.Match.MinSize) {
		return false
	}
	if r.Match.MinAgeDays > 0 {
		if newest.IsZero() || s.now().Sub(newest) < time.Duration(r.Match.MinAgeDays)*24*time.Hour {
			return false
		}
	}
	return true
}

func (s *Set) sizeAgeReason(r *Rule) []string {
	var out []string
	if r.Match.MinSize > 0 {
		out = append(out, fmt.Sprintf("at least %s", humanSize(uint64(r.Match.MinSize))))
	}
	if r.Match.MinAgeDays > 0 {
		out = append(out, fmt.Sprintf("untouched for %d+ days", r.Match.MinAgeDays))
	}
	return out
}

func (s *Set) selectorReason(c *compiled, path string) string {
	m := &c.Match
	switch c.selector {
	case "path":
		return "path is " + s.tilde(path)
	case "glob":
		for _, g := range m.Glob {
			if compileGlob(s.expand(g)).match(splitLower(path)) {
				return "matches " + g
			}
		}
		return "matches " + strings.Join(m.Glob, " or ")
	case "dir_name":
		return "directory named " + filepath.Base(path)
	case "name":
		return "named " + filepath.Base(path)
	default:
		return "file type " + strings.ToLower(filepath.Ext(path))
	}
}

func (s *Set) tilde(p string) string {
	if rest, ok := strings.CutPrefix(p, s.home+"/"); ok {
		return "~/" + rest
	}
	return p
}

// inWorkspace reports whether a project artifact at comps lives in the
// user's own work area. Copies of node_modules and friends also exist inside
// installed tools (~/.vscode/extensions, ~/.claude, ~/.nvm, ...), app bundles
// and ~/Library. Deleting those breaks the tool, so project rules only apply
// under the home directory, outside ~/Library, outside any .app bundle, and
// with no hidden directory between home and the artifact.
func (s *Set) inWorkspace(comps []string) bool {
	if !hasPrefix(comps, s.homeComp, true) {
		return false
	}
	between := comps[len(s.homeComp) : len(comps)-1]
	if len(between) > 0 && between[0] == "library" {
		return false
	}
	for _, c := range between {
		if strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".app") {
			return false
		}
	}
	return true
}

// findUp looks for any of names in dir and its ancestors, up to depth levels,
// never above the home directory's parent or the filesystem root.
func (s *Set) findUp(dir string, names []string, depth int) (root, found string, ok bool) {
	for i := 0; i < depth; i++ {
		if f, ok := anyExists(dir, names); ok {
			return dir, f, true
		}
		if strings.EqualFold(dir, s.home) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", "", false
}

func anyExists(dir string, names []string) (string, bool) {
	for _, n := range names {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			return n, true
		}
	}
	return "", false
}

// Excluded reports whether path, or one of its ancestors, matches a user
// exclusion.
func (s *Set) Excluded(path string) bool {
	comps := splitLower(path)
	for _, g := range s.excludes {
		for i := 1; i <= len(comps); i++ {
			if g.match(comps[:i]) {
				return true
			}
		}
	}
	return false
}

func hasPrefix(comps, prefix []string, strict bool) bool {
	if len(comps) < len(prefix) || (strict && len(comps) == len(prefix)) {
		return false
	}
	for i := range prefix {
		if comps[i] != prefix[i] {
			return false
		}
	}
	return true
}

func humanSize(n uint64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%g TB", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%g GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%g MB", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%g kB", float64(n)/1e3)
	}
	return fmt.Sprintf("%d B", n)
}

// isClean reports whether p is already in filepath.Clean form, cheaply, so
// the hot path can skip Clean's allocation for scanner paths.
func isClean(p string) bool {
	if p == "/" {
		return true
	}
	if p == "" || strings.HasSuffix(p, "/") {
		return false
	}
	return !strings.Contains(p, "//") && !strings.Contains(p, "/./") && !strings.Contains(p, "/../") &&
		!strings.HasSuffix(p, "/.") && !strings.HasSuffix(p, "/..")
}
