// Package classifier applies rules to scan results and produces Findings,
// each with exactly one risk tier.
//
// The tier is the rule's tier, made stricter (never weaker) by:
//   - user exclusions (at least REVIEW), and
//   - the safety layer (PROTECTED for anything safety.Guard protects).
//
// Paths no rule matches are REVIEW under the home directory and PROTECTED
// elsewhere (see DefaultTier).
package classifier

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// Finding is a classified path from a scan.
type Finding struct {
	Path     string      `json:"path"`
	RuleID   string      `json:"rule_id"`
	Category string      `json:"category"`
	Tier     safety.Tier `json:"tier"`
	// RuleTier is the tier the rule assigned, before overrides.
	RuleTier safety.Tier `json:"rule_tier"`
	// Override explains why Tier is stricter than RuleTier.
	Override string `json:"override,omitempty"`

	IsDir        bool      `json:"is_dir"`
	Size         uint64    `json:"size_bytes"`
	ApparentSize uint64    `json:"apparent_size_bytes"`
	Files        uint64    `json:"files"`
	MTime        time.Time `json:"mtime"`
	Newest       time.Time `json:"newest_mtime"`
	Inaccessible bool      `json:"partially_inaccessible,omitempty"`

	Reason         string   `json:"reason"`
	Description    string   `json:"description"`
	RegenerateHint string   `json:"regenerate_hint,omitempty"`
	NativeClean    []string `json:"native_clean,omitempty"`
	NativeOnly     bool     `json:"native_only,omitempty"`
	CleanContents  bool     `json:"clean_contents,omitempty"`

	ProjectRoot  string    `json:"project_root,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`
	Stale        bool      `json:"stale,omitempty"`

	// NestedIn is set when this finding lies inside another finding (an
	// unpruned folder match); that finding's Size excludes this one.
	NestedIn string `json:"nested_in,omitempty"`

	// Dev and Ino identify the object at scan time, for revalidation
	// before deletion.
	Dev uint64 `json:"-"`
	Ino uint64 `json:"-"`
}

// Classifier matches entries during a scan and builds findings after it.
type Classifier struct {
	set   *rules.Set
	guard *safety.Guard
	now   func() time.Time
	// BrewPrefixes are the Homebrew installation prefixes checked for old
	// formula versions. Tests point them at fixtures.
	BrewPrefixes []string

	mu   sync.Mutex
	hits []hit
}

type hit struct {
	entry scanner.Entry
	res   rules.Result
}

// New returns a classifier. now defaults to time.Now.
func New(set *rules.Set, guard *safety.Guard, now func() time.Time) *Classifier {
	if now == nil {
		now = time.Now
	}
	return &Classifier{set: set, guard: guard, now: now, BrewPrefixes: []string{"/opt/homebrew", "/usr/local"}}
}

// Visit is a scanner.Options.Visit hook. Matched directories are pruned:
// they become one finding, and nothing inside them is classified separately.
// The exception is a match whose size/age condition can only be checked
// after the scan (e.g. "Downloads item older than 30 days"): its contents
// are still classified, so a project inside it is not hidden.
func (c *Classifier) Visit(e scanner.Entry) bool {
	res, ok := c.set.Match(rules.Candidate{Path: e.Path, IsDir: e.IsDir, Size: e.Size, MTime: e.MTime})
	if !ok {
		return false
	}
	c.mu.Lock()
	c.hits = append(c.hits, hit{e, res})
	c.mu.Unlock()
	return e.IsDir && !res.Deferred
}

// Findings builds findings from the hits collected during the scan of res.
// Call it before compacting res.Tree. Results are sorted largest first.
func (c *Classifier) Findings(res *scanner.Result) []Finding {
	c.mu.Lock()
	hits := append([]hit(nil), c.hits...)
	c.mu.Unlock()

	artifacts := map[string]bool{}
	for _, h := range hits {
		if h.entry.IsDir {
			artifacts[strings.ToLower(h.entry.Path)] = true
		}
	}
	activity := map[string]time.Time{}

	out := make([]Finding, 0, len(hits))
	for _, h := range hits {
		r := h.res.Rule
		f := Finding{
			Path: h.entry.Path, RuleID: r.ID, Category: r.Category,
			RuleTier: r.Tier, Tier: r.Tier,
			IsDir: h.entry.IsDir, MTime: h.entry.MTime,
			Reason: h.res.Reason, Description: r.Description, RegenerateHint: r.RegenerateHint,
			NativeClean: r.NativeClean, NativeOnly: r.NativeOnly, CleanContents: r.CleanContents,
			ProjectRoot: h.res.ProjectRoot, Dev: h.entry.Dev, Ino: h.entry.Ino,
		}
		if f.IsDir {
			n := res.Tree.Find(f.Path)
			if n == nil {
				continue // not in this scan's tree (e.g. scan root changed)
			}
			f.Size, f.ApparentSize, f.Files, f.Newest, f.Inaccessible = n.Size, n.ApparentSize, n.FileCount, n.Newest, n.Inaccessible
			if h.res.Deferred && !c.set.SizeAgeOK(r, f.Size, f.Newest) {
				continue
			}
		} else {
			f.Size, f.ApparentSize, f.Files, f.Newest = h.entry.Size, h.entry.ApparentSize, 1, h.entry.MTime
		}

		c.applyOverrides(&f)

		if f.ProjectRoot != "" {
			key := strings.ToLower(f.ProjectRoot)
			t, ok := activity[key]
			if !ok {
				t = lastActivity(f.ProjectRoot, res.Tree, artifacts)
				activity[key] = t
			}
			f.LastActivity = t
			if r.StaleAfterDays > 0 && !t.IsZero() {
				f.Stale = c.now().Sub(t) > time.Duration(r.StaleAfterDays)*24*time.Hour
			}
		}
		out = append(out, f)
	}
	out = append(out, c.homebrewOldVersions(res.Tree)...)
	out = carveNested(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// carveNested resolves findings inside other findings, which only happens
// under a deferred (unpruned) match such as an old Downloads folder. Inner
// findings are kept, since they are the more specific and more actionable
// ones, and the outer finding's size is reduced to what remains, so no byte
// is counted twice.
func carveNested(fs []Finding) []Finding {
	sort.Slice(fs, func(i, j int) bool { return len(fs[i].Path) < len(fs[j].Path) })
	for i := range fs {
		if !fs[i].IsDir {
			continue
		}
		prefix := strings.ToLower(fs[i].Path) + "/"
		for j := i + 1; j < len(fs); j++ {
			if !strings.HasPrefix(strings.ToLower(fs[j].Path), prefix) || fs[j].NestedIn != "" {
				continue
			}
			fs[j].NestedIn = fs[i].Path
			fs[i].Size -= min(fs[i].Size, fs[j].Size)
			fs[i].ApparentSize -= min(fs[i].ApparentSize, fs[j].ApparentSize)
			fs[i].Files -= min(fs[i].Files, fs[j].Files)
		}
	}
	return fs
}

// applyOverrides makes f.Tier stricter where exclusions or the safety layer
// require it. It never makes a tier less strict.
func (c *Classifier) applyOverrides(f *Finding) {
	if c.set.Excluded(f.Path) && f.Tier < safety.TierReview {
		f.Tier = safety.TierReview
		f.Override = "excluded by your config"
	}
	// Native-only findings are reclaimed by their tool (brew, docker, xcrun);
	// sweep never deletes their files, so path protection does not apply.
	if f.NativeOnly && f.RuleID != "" {
		if r, ok := c.set.ByID(f.RuleID); ok && !r.User && r.NativeOnly {
			return
		}
	}
	if reason, ok := c.guard.Protected(f.Path); ok && f.Tier < safety.TierProtected {
		f.Tier = safety.TierProtected
		f.Override = "safety layer: " + reason
	}
}

// homebrewOldVersions finds formula versions in a Homebrew Cellar other than
// the one linked from <prefix>/opt/<formula>. Formulae whose current version
// cannot be determined are left alone.
func (c *Classifier) homebrewOldVersions(tree *scanner.Node) []Finding {
	r, ok := c.set.ByID("homebrew-old-versions")
	if !ok {
		return nil
	}
	var out []Finding
	for _, prefix := range c.BrewPrefixes {
		cellar := tree.Find(filepath.Join(prefix, "Cellar"))
		if cellar == nil {
			continue
		}
		for _, formula := range cellar.Children {
			if len(formula.Children) < 2 {
				continue
			}
			target, err := os.Readlink(filepath.Join(prefix, "opt", formula.Name))
			if err != nil {
				continue
			}
			current := filepath.Base(target)
			for _, v := range formula.Children {
				if v.Name == current {
					continue
				}
				out = append(out, Finding{
					Path: filepath.Join(prefix, "Cellar", formula.Name, v.Name), RuleID: r.ID, Category: r.Category,
					Tier: r.Tier, RuleTier: r.Tier, IsDir: true, Size: v.Size, ApparentSize: v.ApparentSize,
					Files: v.FileCount, MTime: v.MTime, Newest: v.Newest,
					Reason:      fmt.Sprintf("%s %s is installed but %s is the linked version", formula.Name, v.Name, current),
					Description: r.Description, RegenerateHint: r.RegenerateHint,
					NativeClean: r.NativeClean, NativeOnly: r.NativeOnly,
				})
			}
		}
	}
	return out
}

// DefaultTier is the tier for paths no rule matches: REVIEW under the home
// directory (likely your data), PROTECTED elsewhere.
func (c *Classifier) DefaultTier(path string) safety.Tier {
	home := strings.ToLower(c.guard.Home())
	p := strings.ToLower(filepath.Clean(path))
	if p == home || strings.HasPrefix(p, home+"/") {
		return safety.TierReview
	}
	return safety.TierProtected
}

// lastActivity is the most recent sign of work in a project: the newest
// file modification outside build artifacts, or the last git HEAD update,
// whichever is later.
func lastActivity(root string, tree *scanner.Node, artifacts map[string]bool) time.Time {
	t := gitHeadTime(root)
	if n := tree.Find(root); n != nil {
		if nt := newestExcluding(n, root, artifacts); nt.After(t) {
			t = nt
		}
	}
	return t
}

func newestExcluding(n *scanner.Node, path string, artifacts map[string]bool) time.Time {
	t := n.OwnNewest
	for _, ch := range n.Children {
		cp := filepath.Join(path, ch.Name)
		if artifacts[strings.ToLower(cp)] {
			continue
		}
		if ct := newestExcluding(ch, cp, artifacts); ct.After(t) {
			t = ct
		}
	}
	return t
}

// gitHeadTime returns the timestamp of the last entry in .git/logs/HEAD
// (the last commit, checkout, or pull), or zero if unavailable. It reads the
// file directly rather than running git.
func gitHeadTime(root string) time.Time {
	f, err := os.Open(filepath.Join(root, ".git", "logs", "HEAD"))
	if err != nil {
		return time.Time{}
	}
	defer func() { _ = f.Close() }()
	const tail = 4096
	fi, err := f.Stat()
	if err != nil {
		return time.Time{}
	}
	off := max(fi.Size()-tail, 0)
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return time.Time{}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	return parseReflogTime(lines[len(lines)-1])
}

// parseReflogTime parses "<old> <new> Name <email> <unix-ts> <tz>\tmessage".
func parseReflogTime(line string) time.Time {
	head, _, _ := strings.Cut(line, "\t")
	fields := strings.Fields(head)
	if len(fields) < 2 {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(fields[len(fields)-2], 10, 64)
	if err != nil || ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}
