// Package cleaner turns findings into a deletion plan and executes it.
//
// Every layer fails closed:
//   - BuildPlan only ever selects SAFE findings, plus CAUTION ones when
//     asked; REVIEW and PROTECTED can never enter a plan (the tier check here
//     and safety.Guard.CheckDeletable both enforce it).
//   - Execute revalidates each item immediately before touching it
//     (safety.Guard.Revalidate) and refuses directories that contain git
//     repositories or .env files.
//   - Deletion moves items to the Trash unless --permanent was given, and
//     every action is written to the audit log.
package cleaner

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
)

// Method is how an item is cleaned.
type Method string

const (
	MethodTrash     Method = "trash"
	MethodPermanent Method = "permanent"
	MethodNative    Method = "native"
)

// Selector narrows which findings to clean. Empty lists mean "no filter".
type Selector struct {
	// MaxTier is TierSafe (default) or TierCaution. Anything stricter is
	// rejected by BuildPlan.
	MaxTier    safety.Tier
	Categories []string // exact, case-insensitive
	Rules      []string // rule ids
	Names      []string // final path component; globs allowed, e.g. node_modules, .next
	Under      []string // only paths inside these directories
	Excludes   []string // globs ("~" and "**" allowed); matching paths are left alone
	// OlderThan keeps items untouched for at least this long. For project
	// artifacts "untouched" means the project's last activity, so a recently
	// reinstalled node_modules in an abandoned project still qualifies.
	OlderThan time.Duration
	MinSize   uint64
	StaleOnly bool
}

// Options configures BuildPlan.
type Options struct {
	Permanent  bool
	SkipNative bool
	Now        time.Time
	// LookPath reports whether a native command is installed (exec.LookPath).
	LookPath func(string) (string, error)
	// RunningApps holds lowercased bundle IDs of running apps; their cache
	// folders are left alone (cleaning a running app's cache can corrupt it).
	RunningApps map[string]bool
	// Snapshots adds thinning local Time Machine snapshots to the plan.
	Snapshots bool
	// OpenFiles holds the paths running processes have open; items with
	// anything open inside are left alone. Nil means none are known.
	OpenFiles *macos.OpenFiles
}

// SnapshotsRuleID identifies the Time Machine snapshot item in plans and the
// audit log. It is not a scan finding: snapshots are not files.
const SnapshotsRuleID = "tm-local-snapshots"

// Item is one planned action.
type Item struct {
	classifier.Finding
	Method Method `json:"method"`
	// Command is the native command for MethodNative items.
	Command []string `json:"command,omitempty"`
	// Contents means the directory is emptied rather than removed.
	Contents bool `json:"contents,omitempty"`
}

// Left is a finding the selection matched but which will not be cleaned,
// with the reason.
type Left struct {
	Path   string      `json:"path"`
	Size   uint64      `json:"size_bytes"`
	Tier   safety.Tier `json:"tier"`
	RuleID string      `json:"rule_id"`
	Reason string      `json:"reason"`
}

// Plan is the result of BuildPlan.
type Plan struct {
	ScanRoot  string    `json:"scan_root"`
	ScannedAt time.Time `json:"scanned_at"`
	MaxTier   string    `json:"max_tier"`
	Permanent bool      `json:"permanent"`
	Items     []Item    `json:"items"`
	// Left lists selected findings that cannot be cleaned as asked.
	Left []Left `json:"left_out"`
	// NeverCleaned counts selected REVIEW and PROTECTED findings.
	NeverCleaned     int    `json:"never_cleaned"`
	NeverCleanedSize uint64 `json:"never_cleaned_bytes"`
	// FilteredOut counts findings that did not match the selection.
	FilteredOut int `json:"filtered_out"`
}

// Total is the size of everything in the plan.
func (p *Plan) Total() uint64 {
	var n uint64
	for _, it := range p.Items {
		n += it.Size
	}
	return n
}

// NativeGroup is one native command and the items it reclaims.
type NativeGroup struct {
	Command []string
	Items   []Item
}

// NativeGroups returns the distinct native commands in the plan, in order.
func (p *Plan) NativeGroups() []NativeGroup {
	var out []NativeGroup
	idx := map[string]int{}
	for _, it := range p.Items {
		if it.Method != MethodNative {
			continue
		}
		key := strings.Join(it.Command, "\x00")
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, NativeGroup{Command: it.Command})
		}
		out[i].Items = append(out[i].Items, it)
	}
	return out
}

// BuildPlan selects findings from a saved scan. It reads nothing from disk
// except to check whether native commands are installed.
func BuildPlan(s *cache.Scan, sel Selector, set *rules.Set, guard *safety.Guard, o Options) (*Plan, error) {
	if sel.MaxTier == safety.TierUnknown {
		sel.MaxTier = safety.TierSafe
	}
	if !sel.MaxTier.Deletable() {
		return nil, fmt.Errorf("tier %s can never be cleaned; use safe or caution", sel.MaxTier)
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	var excl *rules.Set
	if len(sel.Excludes) > 0 {
		var err error
		excl, err = rules.NewSet(rules.Options{Home: guard.Home(), Excludes: sel.Excludes})
		if err != nil {
			return nil, fmt.Errorf("--exclude: %w", err)
		}
	}
	for _, n := range sel.Names {
		if _, err := filepath.Match(n, ""); err != nil || strings.Contains(n, "/") {
			return nil, fmt.Errorf("--name %q must be a file or folder name (globs allowed)", n)
		}
	}

	p := &Plan{ScanRoot: s.Result.Root, ScannedAt: s.Result.FinishedAt, MaxTier: sel.MaxTier.String(), Permanent: o.Permanent}
	trash := strings.ToLower(guard.Expand("~/.Trash"))
	owners := appDataRoots(guard)
	leave := func(f classifier.Finding, format string, args ...any) {
		p.Left = append(p.Left, Left{Path: f.Path, Size: f.Size, Tier: f.Tier, RuleID: f.RuleID, Reason: fmt.Sprintf(format, args...)})
	}

	for _, f := range s.Findings {
		if !sel.matches(f, guard, o.Now) {
			p.FilteredOut++
			continue
		}
		if f.Size == 0 && f.Files == 0 && !f.CleanContents {
			continue // an empty folder: nothing to reclaim
		}
		if excl != nil && excl.Excluded(f.Path) {
			leave(f, "matches --exclude")
			continue
		}
		if !f.Tier.Deletable() {
			p.NeverCleaned++
			p.NeverCleanedSize += f.Size
			continue
		}
		if f.Tier > sel.MaxTier {
			leave(f, "%s item; add --tier caution to include it", f.Tier)
			continue
		}
		r, ok := set.ByID(f.RuleID)
		if !ok {
			leave(f, "rule %q no longer exists; run 'sweep scan' again", f.RuleID)
			continue
		}
		if app := runningOwner(f.Path, owners, o.RunningApps); app != "" {
			leave(f, "%s is running; quit it and run clean again", app)
			continue
		}

		it := Item{Finding: f}
		if len(r.NativeClean) > 0 {
			switch {
			case o.SkipNative && r.NativeOnly:
				leave(f, "only cleanable by running `%s` (skipped by --skip-native)", strings.Join(r.NativeClean, " "))
				continue
			case o.SkipNative:
				// fall through to deleting files
			case !rules.AllowedNative(r.NativeClean[0]):
				leave(f, "native command %q is not allowed", r.NativeClean[0])
				continue
			case !installed(o.LookPath, r.NativeClean[0]):
				if r.NativeOnly {
					leave(f, "needs `%s`, but %s is not installed", strings.Join(r.NativeClean, " "), r.NativeClean[0])
					continue
				}
			default:
				it.Method, it.Command = MethodNative, r.NativeClean
				p.Items = append(p.Items, it)
				continue
			}
		}

		if cmd, open := o.OpenFiles.Under(f.Path); open {
			leave(f, "in use by %s", cmd)
			continue
		}
		it.Contents = r.CleanContents
		lp := strings.ToLower(f.Path)
		inTrash := lp == trash || strings.HasPrefix(lp, trash+"/")
		switch {
		case inTrash && !o.Permanent:
			leave(f, "emptying the Trash is permanent; add --permanent to include it")
			continue
		case o.Permanent:
			it.Method = MethodPermanent
		default:
			it.Method = MethodTrash
		}

		// Static safety check now, so the plan never shows anything the
		// executor would refuse. Contents items are checked per child at
		// execution time; the container itself must not be protected.
		if it.Contents {
			if reason, bad := guard.Protected(f.Path); bad {
				leave(f, "safety layer: %s", reason)
				continue
			}
		} else if err := guard.CheckDeletable(f.Path, f.Tier); err != nil {
			leave(f, "safety layer: %v", reasonOf(err))
			continue
		}
		p.Items = append(p.Items, it)
	}

	if o.Snapshots {
		snap := classifier.Finding{
			Path: "Time Machine local snapshots", RuleID: SnapshotsRuleID, Category: "System: Snapshots",
			Tier: safety.TierCaution, RuleTier: safety.TierCaution, NativeOnly: true,
			Description: "Local Time Machine snapshots. macOS frees them on its own when space runs low; this asks it to now.",
		}
		switch {
		case len(s.Snapshots) == 0:
			leave(snap, "no local Time Machine snapshots were found at scan time")
		case o.SkipNative:
			leave(snap, "thinning snapshots runs tmutil (skipped by --skip-native)")
		case !installed(o.LookPath, "tmutil"):
			leave(snap, "tmutil is not available")
		default:
			snap.Reason = fmt.Sprintf("%d local snapshots", len(s.Snapshots))
			p.Items = append(p.Items, Item{Finding: snap, Method: MethodNative, Command: macos.ThinSnapshotsCommand})
		}
	}

	sort.SliceStable(p.Items, func(i, j int) bool { return p.Items[i].Size > p.Items[j].Size })
	sort.SliceStable(p.Left, func(i, j int) bool { return p.Left[i].Size > p.Left[j].Size })
	return p, nil
}

// appDataRoots are the folders whose first-level entries are named after the
// app that owns them: a bundle ID (Caches, Containers), a team-prefixed
// group ID (Group Containers) or the app's name (Application Support).
func appDataRoots(guard *safety.Guard) []string {
	var out []string
	for _, p := range []string{"~/Library/Caches", "~/Library/Containers", "~/Library/Group Containers", "~/Library/Application Support"} {
		out = append(out, strings.ToLower(guard.Expand(p))+"/")
	}
	return out
}

// appFolderAliases maps Application Support folder names to the running
// app's name where the two differ.
var appFolderAliases = map[string]string{
	"google":        "google chrome",
	"bravesoftware": "brave browser",
	"claude-3p":     "claude",
	"code":          "visual studio code",
}

// runningOwner returns the running app (as lsappinfo names it) that owns an
// app-data folder (~/Library/Caches/<bundle id>, ~/Library/Application
// Support/<app>, ...), or "". Cleaning a running app's cache can corrupt it.
func runningOwner(path string, roots []string, running map[string]bool) string {
	if len(running) == 0 {
		return ""
	}
	lp := strings.ToLower(path)
	for _, root := range roots {
		if !strings.HasPrefix(lp, root) {
			continue
		}
		name, _, _ := strings.Cut(lp[len(root):], "/")
		_, group, _ := strings.Cut(name, ".") // Group Containers: TEAMID.com.example.app
		for _, n := range []string{name, appFolderAliases[name], group, strings.TrimPrefix(group, "group.")} {
			if n != "" && running[n] {
				return n
			}
		}
	}
	return ""
}

func installed(lookPath func(string) (string, error), cmd string) bool {
	if lookPath == nil {
		return false
	}
	_, err := lookPath(cmd)
	return err == nil
}

func reasonOf(err error) string {
	var v *safety.Violation
	if errors.As(err, &v) {
		return v.Reason
	}
	return err.Error()
}

// matches applies the user's filters (not tiers) to a finding.
func (sel *Selector) matches(f classifier.Finding, guard *safety.Guard, now time.Time) bool {
	if len(sel.Categories) > 0 && !containsFold(sel.Categories, f.Category) {
		return false
	}
	if len(sel.Rules) > 0 && !containsFold(sel.Rules, f.RuleID) {
		return false
	}
	if len(sel.Names) > 0 {
		base := strings.ToLower(filepath.Base(f.Path))
		ok := false
		for _, n := range sel.Names {
			if m, _ := filepath.Match(strings.ToLower(n), base); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(sel.Under) > 0 {
		ok := false
		lp := strings.ToLower(f.Path)
		for _, u := range sel.Under {
			lu := strings.ToLower(filepath.Clean(guard.Expand(u)))
			if lp == lu || strings.HasPrefix(lp, strings.TrimSuffix(lu, "/")+"/") {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if sel.MinSize > 0 && f.Size < sel.MinSize {
		return false
	}
	if sel.StaleOnly && !f.Stale {
		return false
	}
	if sel.OlderThan > 0 {
		last := f.Newest
		if f.ProjectRoot != "" && !f.LastActivity.IsZero() {
			last = f.LastActivity
		}
		if last.IsZero() || now.Sub(last) < sel.OlderThan {
			return false
		}
	}
	return true
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), s) {
			return true
		}
	}
	return false
}
