// Package safety implements the non-negotiable deletion guards from SPEC §8.
//
// Nothing here is configurable: rules and user config can only make sweep
// stricter, never weaker. Every check fails closed. If a path cannot be
// proven safe, it is refused.
package safety

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// MinHomeDepth is the minimum number of components a deletable path must have
// below a home directory. ~/Downloads (depth 1) is refused, while
// ~/Downloads/old.dmg and ~/code/app/node_modules (depth 2+) may proceed to
// the other checks.
const MinHomeDepth = 2

// Guard decides whether a path may be deleted. Build one with NewGuard, which
// takes the home directory as a parameter so tests can redirect it.
type Guard struct {
	homes []string // canonical home path, plus its symlink-resolved form
	roots []compiledRoot
}

type compiledRoot struct {
	display string
	comps   []string
	reason  string
	except  func([]string) bool
}

// NewGuard returns a Guard for the given absolute home directory.
func NewGuard(home string) (*Guard, error) {
	if home == "" || !filepath.IsAbs(home) {
		return nil, fmt.Errorf("safety: home must be an absolute path, got %q", home)
	}
	h := canonical(home)
	if h == "/" {
		return nil, errors.New("safety: home cannot be /")
	}
	g := &Guard{homes: []string{h}}
	if r, err := filepath.EvalSymlinks(h); err == nil {
		if r = canonical(r); !strings.EqualFold(r, h) {
			g.homes = append(g.homes, r)
		}
	}

	for _, spec := range protectedRoots {
		if !strings.HasPrefix(spec.pattern, "~/") {
			g.roots = append(g.roots, compile(spec.pattern, spec.pattern, spec))
			continue
		}
		for _, h := range g.homes {
			g.roots = append(g.roots, compile(spec.pattern, filepath.Join(h, spec.pattern[2:]), spec))
		}
	}
	return g, nil
}

func compile(display, abs string, spec rootSpec) compiledRoot {
	return compiledRoot{display: display, comps: splitLower(abs), reason: spec.reason, except: spec.except}
}

// Home returns the home directory the guard was built with.
func (g *Guard) Home() string { return g.homes[0] }

// Expand replaces a leading "~" with the guard's home directory.
func (g *Guard) Expand(p string) string {
	if p == "~" {
		return g.homes[0]
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(g.homes[0], p[2:])
	}
	return p
}

// CheckPath applies the path sanity rules (SPEC §8.3). It rejects empty,
// relative, unexpanded "~", traversal ("..") and overly shallow paths. Depth
// rules apply both to the path as written and to its symlink-resolved form.
func (g *Guard) CheckPath(p string) error {
	switch {
	case p == "":
		return violation(ErrUnsafePath, p, "empty path")
	case strings.ContainsRune(p, 0):
		return violation(ErrUnsafePath, p, "path contains a NUL byte")
	case strings.HasPrefix(p, "~"):
		return violation(ErrUnsafePath, p, "unexpanded ~")
	case !filepath.IsAbs(p):
		return violation(ErrUnsafePath, p, "relative path")
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return violation(ErrUnsafePath, p, "path contains '..'")
		}
	}
	for _, c := range g.candidates(p) {
		if err := g.checkDepth(p, c); err != nil {
			return err
		}
	}
	return nil
}

func (g *Guard) checkDepth(orig, c string) error {
	comps := splitLower(c)
	if len(comps) < 2 {
		return violation(ErrUnsafePath, orig, "path is too shallow (%s)", c)
	}
	// Covers every /Users/<name>, not just the guard's own home.
	if comps[0] == "users" && len(comps) < 2+MinHomeDepth {
		return violation(ErrUnsafePath, orig, "path is too close to a home directory (%s)", c)
	}
	for _, h := range g.homes {
		if within(c, h, false) && len(comps)-len(splitLower(h)) < MinHomeDepth {
			return violation(ErrUnsafePath, orig, "path is too close to the home directory (%s)", c)
		}
	}
	return nil
}

// Protected reports whether p is at, below, or above a protected location.
// It checks the path as written and with symlinks in its parent directories
// resolved, so a symlinked parent cannot smuggle in a protected target.
func (g *Guard) Protected(p string) (reason string, protected bool) {
	for _, c := range g.candidates(p) {
		if r, ok := g.protectedLexical(c); ok {
			return r, true
		}
	}
	return "", false
}

func (g *Guard) protectedLexical(p string) (string, bool) {
	for _, h := range g.homes {
		if strings.EqualFold(p, h) {
			return "home directory", true
		}
	}
	comps := splitLower(p)
	for _, c := range comps {
		if r, ok := protectedComponent(c); ok {
			return r, true
		}
	}
	for _, r := range g.roots {
		if !r.matches(comps) {
			continue
		}
		if len(comps) < len(r.comps) {
			return fmt.Sprintf("contains protected %s (%s)", r.display, r.reason), true
		}
		return fmt.Sprintf("inside protected %s (%s)", r.display, r.reason), true
	}
	return "", false
}

// matches reports whether comps lies at, below, or above the root, comparing
// component by component up to the shorter length.
func (r compiledRoot) matches(comps []string) bool {
	n := min(len(comps), len(r.comps))
	for i := 0; i < n; i++ {
		ok, err := filepath.Match(r.comps[i], comps[i])
		if err != nil || !ok {
			return false
		}
	}
	if r.except != nil && len(comps) > len(r.comps) && r.except(comps) {
		return false
	}
	return true
}

// CheckDeletable is the static gate for anything entering a deletion plan:
// the tier must be deletable, the path must be sane, and it must not touch a
// protected location.
func (g *Guard) CheckDeletable(p string, tier Tier) error {
	if !tier.Deletable() {
		return violation(ErrTier, p, "tier %s is never deletable", tier)
	}
	if err := g.CheckPath(p); err != nil {
		return err
	}
	if reason, ok := g.Protected(p); ok {
		return violation(ErrProtected, p, "%s", reason)
	}
	return nil
}

// Target is a planned deletion as recorded at scan time.
type Target struct {
	Path     string
	RuleID   string
	Tier     Tier
	ScanRoot string
	// Dev and Ino identify the scanned object. When Ino is non-zero,
	// Revalidate refuses the path if it now refers to a different object.
	Dev, Ino uint64
}

// Matcher re-evaluates the rules against a path at deletion time. It returns
// the ID of the matching rule.
type Matcher func(path string, info fs.FileInfo) (ruleID string, ok bool)

// Revalidate runs immediately before a deletion (SPEC §8.2). It guards
// against stale scans and time-of-check/time-of-use swaps by checking that
// the path still exists, is not a symlink, is the same object, is still
// inside the scan root, is still matched by the same rule, and is not
// protected.
func (g *Guard) Revalidate(t Target, match Matcher) error {
	if err := g.CheckDeletable(t.Path, t.Tier); err != nil {
		return err
	}
	if t.RuleID == "" {
		return violation(ErrUnsafePath, t.Path, "no rule id recorded")
	}
	if match == nil {
		return violation(ErrChanged, t.Path, "no matcher to re-verify the rule")
	}
	if t.ScanRoot == "" || !filepath.IsAbs(t.ScanRoot) {
		return violation(ErrUnsafePath, t.Path, "invalid scan root %q", t.ScanRoot)
	}

	fi, err := os.Lstat(t.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return violation(ErrChanged, t.Path, "no longer exists")
	}
	if err != nil {
		return violation(ErrChanged, t.Path, "cannot stat: %v", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return violation(ErrChanged, t.Path, "is now a symlink")
	}
	if t.Ino != 0 {
		dev, ino, ok := FileID(fi)
		if !ok || dev != t.Dev || ino != t.Ino {
			return violation(ErrChanged, t.Path, "was replaced by a different file or directory")
		}
	}

	root := canonical(t.ScanRoot)
	if !within(canonical(t.Path), root, true) ||
		!within(canonical(resolveParents(t.Path)), canonical(resolveExisting(root)), true) {
		return violation(ErrChanged, t.Path, "is outside the scan root %s", t.ScanRoot)
	}
	if id, ok := match(t.Path, fi); !ok || id != t.RuleID {
		return violation(ErrChanged, t.Path, "is no longer matched by rule %q", t.RuleID)
	}
	// Check again after the filesystem reads above, to narrow the window for
	// a parent directory being swapped in the meantime.
	if reason, ok := g.Protected(t.Path); ok {
		return violation(ErrProtected, t.Path, "%s", reason)
	}
	return nil
}

// FileID returns the (device, inode) pair for fi. The scanner and the
// guard must agree on this encoding.
func FileID(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(uint32(st.Dev)), st.Ino, true //nolint:gosec // Dev is int32 on darwin; reinterpret bits.
}

// candidates returns the forms of p to check: the cleaned path itself and,
// if different, the path with symlinks in its parent directories resolved.
func (g *Guard) candidates(p string) []string {
	c := canonical(p)
	out := []string{c}
	if r := canonical(resolveParents(c)); !strings.EqualFold(r, c) {
		out = append(out, r)
	}
	return out
}

// macOS exposes these top-level directories as symlinks into /private.
var aliases = [][2]string{
	{"/etc", "/private/etc"},
	{"/var", "/private/var"},
	{"/tmp", "/private/tmp"},
}

// canonical cleans p and rewrites macOS /private aliases so lexical checks
// work without touching the filesystem.
func canonical(p string) string {
	p = filepath.Clean(p)
	lp := strings.ToLower(p)
	for _, a := range aliases {
		if lp == a[0] || strings.HasPrefix(lp, a[0]+"/") {
			return a[1] + p[len(a[0]):]
		}
	}
	return p
}

// resolveParents resolves symlinks in p's parent directories but never in
// the final component, which is the object to be deleted.
func resolveParents(p string) string {
	if p == "/" {
		return p
	}
	return filepath.Join(resolveExisting(filepath.Dir(p)), filepath.Base(p))
}

// resolveExisting resolves symlinks in the longest existing prefix of p and
// appends the rest unchanged.
func resolveExisting(p string) string {
	cur, rest := p, ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func splitLower(p string) []string {
	p = strings.Trim(strings.ToLower(filepath.Clean(p)), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// within reports whether child is parent or lies below it (strictly below if
// strict). The comparison is case-insensitive.
func within(child, parent string, strict bool) bool {
	c, p := splitLower(child), splitLower(parent)
	if len(c) < len(p) || (strict && len(c) == len(p)) {
		return false
	}
	for i := range p {
		if c[i] != p[i] {
			return false
		}
	}
	return true
}
