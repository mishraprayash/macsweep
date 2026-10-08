package classifier

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// Explanation describes what a path is and how sweep treats it.
type Explanation struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	IsDir  bool   `json:"is_dir"`

	Tier         safety.Tier `json:"tier"`
	Unclassified bool        `json:"unclassified"`
	// MatchedPath is the path the rule matched. It differs from Path when
	// Path lies inside a matched directory (e.g. a file in node_modules).
	MatchedPath    string   `json:"matched_path,omitempty"`
	RuleID         string   `json:"rule_id,omitempty"`
	RuleSource     string   `json:"rule_source,omitempty"`
	Category       string   `json:"category,omitempty"`
	RuleTier       string   `json:"rule_tier,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Description    string   `json:"description,omitempty"`
	RegenerateHint string   `json:"regenerate_hint,omitempty"`
	NativeClean    []string `json:"native_clean,omitempty"`
	NativeOnly     bool     `json:"native_only,omitempty"`
	CleanContents  bool     `json:"clean_contents,omitempty"`
	Override       string   `json:"override,omitempty"`
	// Pending notes conditions that could not be checked without scan data.
	Pending string `json:"pending,omitempty"`
	// InScan is true when the path lies under the saved scan's root.
	InScan bool `json:"in_scan"`

	ProjectRoot  string    `json:"project_root,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`
	Stale        bool      `json:"stale,omitempty"`

	Size      uint64    `json:"size_bytes,omitempty"`
	SizeKnown bool      `json:"size_known"`
	ScannedAt time.Time `json:"scanned_at,omitempty"`
}

// ScanData is the optional saved scan used to fill in sizes and staleness.
type ScanData struct {
	Result   *scanner.Result
	Findings []Finding
}

// Explain classifies a live path. It evaluates rules against the path's
// ancestors first: like the scanner, the outermost matching directory wins,
// so a file inside node_modules is explained as part of node_modules.
func (c *Classifier) Explain(path string, data *ScanData) Explanation {
	path = filepath.Clean(path)
	e := Explanation{Path: path}
	fi, err := os.Lstat(path)
	if err == nil {
		e.Exists, e.IsDir = true, fi.IsDir()
	}

	var match rules.Result
	matched := false
	for _, anc := range ancestors(path, c.guard.Home()) {
		cand := rules.Candidate{Path: anc, IsDir: true}
		if anc == path {
			cand.IsDir = e.IsDir
			if e.Exists && !e.IsDir {
				cand.MTime = fi.ModTime()
				cand.Size = allocatedSize(fi)
			}
		}
		if res, ok := c.set.Match(cand); ok && (anc == path || !res.Deferred) {
			// A deferred ancestor match (e.g. an old Downloads folder) does
			// not swallow its contents during a scan, so it does not here.
			match, matched = res, true
			e.MatchedPath = anc
			break
		}
	}

	if data != nil && data.Result != nil {
		e.ScannedAt = data.Result.FinishedAt
		root := strings.ToLower(filepath.Clean(data.Result.Root))
		lp := strings.ToLower(path)
		e.InScan = lp == root || strings.HasPrefix(lp, strings.TrimSuffix(root, "/")+"/")
	}
	if f := findFinding(data, e.MatchedPath); f != nil {
		e.Size, e.SizeKnown = f.Size, true
		e.LastActivity, e.Stale = f.LastActivity, f.Stale
	} else if data != nil && data.Result != nil {
		if n := data.Result.Tree.Find(path); n != nil {
			e.Size, e.SizeKnown = n.Size, true
		}
	}
	if !e.SizeKnown && e.Exists && !e.IsDir {
		e.Size, e.SizeKnown = allocatedSize(fi), true
	}

	if matched {
		r := match.Rule
		e.RuleID, e.RuleSource, e.Category, e.RuleTier = r.ID, r.Source, r.Category, r.Tier.String()
		e.Tier = r.Tier
		e.Reason, e.Description, e.RegenerateHint = match.Reason, r.Description, r.RegenerateHint
		e.NativeClean, e.NativeOnly, e.CleanContents = r.NativeClean, r.NativeOnly, r.CleanContents
		e.ProjectRoot = match.ProjectRoot
		if match.Deferred {
			if f := findFinding(data, e.MatchedPath); f == nil {
				if data == nil || data.Result == nil || data.Result.Tree.Find(e.MatchedPath) == nil {
					e.Pending = "size/age conditions need scan data; run 'sweep scan' on a folder containing this path"
				} else {
					// Scanned, but the rule's size/age condition did not hold.
					matched = false
				}
			}
		}
	}
	if !matched {
		e = Explanation{
			Path: e.Path, Exists: e.Exists, IsDir: e.IsDir, Size: e.Size, SizeKnown: e.SizeKnown, ScannedAt: e.ScannedAt, InScan: e.InScan,
			Unclassified: true, Tier: c.DefaultTier(path), RuleTier: c.DefaultTier(path).String(),
		}
	}

	f := Finding{Path: path, Tier: e.Tier}
	c.applyOverrides(&f)
	if matched && e.MatchedPath != path {
		// The matched ancestor's tier applies to everything inside it; it
		// must also be checked against the safety layer itself.
		af := Finding{Path: e.MatchedPath, Tier: e.Tier}
		c.applyOverrides(&af)
		if af.Tier > f.Tier {
			f = af
		}
	}
	e.Tier, e.Override = f.Tier, f.Override
	return e
}

// ancestors returns path's ancestors from the shallowest, then path itself.
// For paths inside the home directory the walk starts below home, the same
// boundary a scan of home has; otherwise it starts below the filesystem root.
func ancestors(path, home string) []string {
	stop := "/"
	if rest, ok := strings.CutPrefix(strings.ToLower(path), strings.ToLower(home)+"/"); ok && rest != "" {
		stop = home
	}
	var out []string
	for p := path; !strings.EqualFold(p, stop) && p != "/" && p != "."; p = filepath.Dir(p) {
		out = append(out, p)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func findFinding(data *ScanData, path string) *Finding {
	if data == nil || path == "" {
		return nil
	}
	for i := range data.Findings {
		if strings.EqualFold(data.Findings[i].Path, path) {
			return &data.Findings[i]
		}
	}
	return nil
}

func allocatedSize(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(max(st.Blocks, 0)) * 512
	}
	return uint64(max(fi.Size(), 0))
}
