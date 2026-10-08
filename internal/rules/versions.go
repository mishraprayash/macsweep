package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// versionStore is a folder of side-by-side tool versions (one entry per
// version) where everything except the version in use can go. Its rule is
// synthetic: Match decides membership through matchVersion, so the scan,
// explain, and the cleaner's re-check right before deleting all agree.
type versionStore struct {
	ruleID string
	dir    string // "~/"-relative
	// keep returns the entries in use. An empty result means the current
	// version could not be determined, and then nothing is offered.
	keep func(s *Set, dir string, installed []string) map[string]bool
}

var versionStores = []versionStore{
	{ruleID: "nvm-old-node-versions", dir: "~/.nvm/versions/node", keep: nvmKeep},
	{ruleID: "claude-code-old-versions", dir: "~/.local/share/claude/versions", keep: claudeKeep},
	{ruleID: "claude-desktop-old-cli-versions", dir: "~/Library/Application Support/Claude/claude-code", keep: newestKeep},
	{ruleID: "claude-desktop-old-cli-versions", dir: "~/Library/Application Support/Claude/claude-code-vm", keep: newestKeep},
	{ruleID: "claude-desktop-old-cli-versions", dir: "~/Library/Application Support/Claude-3p/claude-code", keep: newestKeep},
	{ruleID: "claude-desktop-old-cli-versions", dir: "~/Library/Application Support/Claude-3p/claude-code-vm", keep: newestKeep},
}

// matchVersion decides entries of version stores. It runs before every other
// rule (see Match), so no rule can claim the version in use: isStore reports
// that path is a store entry, and then ok says whether it is an old version.
// The parent check compares lengths first and allocates nothing, since Match
// runs on every scanned entry.
func (s *Set) matchVersion(path string) (res Result, ok, isStore bool) {
	parent := path[:strings.LastIndexByte(path, '/')]
	for _, vs := range s.stores {
		if len(parent) != len(vs.abs) || !strings.EqualFold(parent, vs.abs) {
			continue
		}
		reason, old := s.oldVersion(vs, path)
		if !old {
			return Result{}, false, true
		}
		return Result{Rule: s.byID[vs.ruleID].Rule, Reason: reason}, true, true
	}
	return Result{}, false, false
}

// oldVersion reports whether path, an entry of vs, is a version other than
// the one in use. It reads the live filesystem, so a re-check right before
// deleting sees the current state.
func (s *Set) oldVersion(vs storeDir, path string) (string, bool) {
	name := path[strings.LastIndexByte(path, '/')+1:]
	if _, valid := parseVersion(name); !valid {
		return "", false
	}
	installed := listVersions(vs.abs)
	if !slices.Contains(installed, name) {
		return "", false
	}
	keep := vs.keep(s, vs.abs, installed)
	if len(keep) == 0 || keep[name] {
		return "", false
	}
	return fmt.Sprintf("%s is installed but %s is the version in use", name, joinKeys(keep)), true
}

// storeDir is a version store whose rule is in the set.
type storeDir struct {
	versionStore
	abs string
}

func (s *Set) compileStores() {
	for _, vs := range versionStores {
		if c, ok := s.byID[vs.ruleID]; ok && c.Synthetic && !c.User {
			s.stores = append(s.stores, storeDir{vs, s.expand(vs.dir)})
		}
	}
}

// listVersions returns the entries of dir that look like versions.
func listVersions(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if _, ok := parseVersion(e.Name()); ok {
			out = append(out, e.Name())
		}
	}
	return out
}

// nvmKeep keeps the version nvm's "default" alias resolves to and the one
// active in the current shell ($NVM_BIN). If the default cannot be resolved
// to an installed version ("system", a missing alias, an uninstalled LTS),
// nothing is offered: which versions matter is then unknown.
func nvmKeep(s *Set, dir string, installed []string) map[string]bool {
	def := resolveNvmAlias(filepath.Join(filepath.Dir(filepath.Dir(dir)), "alias"), "default", installed)
	if def == "" {
		return nil
	}
	keep := map[string]bool{def: true}
	if bin := s.getenv("NVM_BIN"); bin != "" {
		v := filepath.Dir(filepath.Clean(bin))
		if samePath(filepath.Dir(v), dir) {
			keep[filepath.Base(v)] = true
		} else if strings.Contains(v, "/versions/node/") {
			return nil // a version from a store we cannot match up: keep all
		}
	}
	return keep
}

// samePath compares two directories the way APFS does: case-insensitively,
// and after resolving symlinks (e.g. ~/.nvm linked elsewhere).
func samePath(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && strings.EqualFold(ra, rb)
}

// resolveNvmAlias follows nvm aliases ("default" -> "lts/*" -> "lts/jod" ->
// "22") to an installed version, the way nvm does: a partial version picks
// the newest installed match.
func resolveNvmAlias(aliasDir, name string, installed []string) string {
	val := name
	for range 10 {
		switch val {
		case "node", "stable":
			return newest(installed, "")
		}
		if !strings.Contains(val, "..") {
			if b, err := os.ReadFile(filepath.Join(aliasDir, val)); err == nil {
				val = strings.TrimSpace(string(b))
				continue
			}
		}
		if val == name {
			return "" // the alias itself does not exist
		}
		return newest(installed, strings.TrimPrefix(val, "v"))
	}
	return ""
}

// claudeKeep keeps the version ~/.local/bin/claude points to, and the newest
// one in case an update is being installed.
func claudeKeep(s *Set, dir string, installed []string) map[string]bool {
	target, err := os.Readlink(filepath.Join(s.home, ".local", "bin", "claude"))
	if err != nil {
		return nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(s.home, ".local", "bin", target)
	}
	target = filepath.Clean(target)
	if filepath.Dir(target) != dir {
		return nil
	}
	keep := map[string]bool{filepath.Base(target): true}
	if v := newest(installed, ""); v != "" {
		keep[v] = true
	}
	return keep
}

// newestKeep keeps only the newest version, for stores managed by an app
// that always runs its latest download.
func newestKeep(_ *Set, _ string, installed []string) map[string]bool {
	if v := newest(installed, ""); v != "" {
		return map[string]bool{v: true}
	}
	return nil
}

// newest returns the highest installed version equal to prefix or starting
// with prefix + "." ("" matches all).
func newest(installed []string, prefix string) string {
	var best string
	var bestV []int
	for _, name := range installed {
		bare := strings.TrimPrefix(name, "v")
		if prefix != "" && bare != prefix && !strings.HasPrefix(bare, prefix+".") {
			continue
		}
		v, _ := parseVersion(name)
		if best == "" || compareVersions(v, bestV) > 0 {
			best, bestV = name, v
		}
	}
	return best
}

// parseVersion parses "v22.3.0" or "2.1.294" into its numbers.
func parseVersion(name string) ([]int, bool) {
	parts := strings.Split(strings.TrimPrefix(name, "v"), ".")
	if len(parts) < 2 {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func compareVersions(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

func joinKeys(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		a, _ := parseVersion(ks[i])
		b, _ := parseVersion(ks[j])
		return compareVersions(a, b) < 0
	})
	return strings.Join(ks, " and ")
}
