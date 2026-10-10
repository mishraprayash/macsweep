package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// Report is everything `sweep show` shows, in order. The text and JSON
// renderers both use it, so they always agree.
type Report struct {
	ScanRoot  string    `json:"scan_root"`
	ScannedAt time.Time `json:"scanned_at"`
	// CleanedSinceScan is set when 'sweep clean' ran after the scan.
	CleanedItems int    `json:"cleaned_items_since_scan,omitempty"`
	CleanedBytes uint64 `json:"cleaned_bytes_since_scan,omitempty"`
	WholeDisk    bool   `json:"whole_disk"`
	UnitsNote    string `json:"units_note"`
	ClonesNote   string `json:"clones_note"`

	Disk          *DiskOverview `json:"disk,omitempty"`
	Categories    []Category    `json:"categories"`
	SystemData    []SystemItem  `json:"system_data"`
	Tiers         []TierTotal   `json:"tiers"`
	Candidates    []Item        `json:"cleanup_candidates"`
	StaleProjects []Project     `json:"stale_projects"`
	// SmallStaleProjects counts stale projects under 1 MB reclaimable.
	SmallStaleProjects int    `json:"small_stale_projects"`
	Review             []Item `json:"review"`
	Protected          []Item `json:"protected"`
	NextSteps          []Step `json:"next_steps"`
}

// DiskOverview compares the disk's used space with what the scan found.
type DiskOverview struct {
	Total     uint64 `json:"total_bytes"`
	Used      uint64 `json:"used_bytes"`
	Available uint64 `json:"available_bytes"`
	Scanned   uint64 `json:"scanned_bytes"`
	// OtherVolumes are APFS volumes in the same container that a scan does
	// not walk (Preboot, Recovery, VM, Update).
	OtherVolumes []macos.APFSVolume `json:"other_volumes,omitempty"`
	// Unaccounted is used space attributed to neither the scan nor the other
	// volumes: local snapshots, purgeable space, unreadable paths, metadata.
	Unaccounted uint64 `json:"unaccounted_bytes"`
	// Overcounted is set when the scan found more than is used, which APFS
	// clones cause (each copy is counted at full size).
	Overcounted  uint64   `json:"overcounted_bytes,omitempty"`
	Inaccessible uint64   `json:"inaccessible_paths"`
	Explanation  []string `json:"explanation"`
}

// Category is a slice of the scanned space. Rule categories (Kind "rule")
// come from findings; the rest of the space is grouped by location (Kind
// "location"). Together they add up to the scanned total.
type Category struct {
	Name  string  `json:"name"`
	Kind  string  `json:"kind"`
	Size  uint64  `json:"size_bytes"`
	Share float64 `json:"share"`
}

// SystemItem is one piece of what macOS shows as "System Data".
type SystemItem struct {
	Name        string `json:"name"`
	Explanation string `json:"explanation"`
	Size        uint64 `json:"size_bytes"`
	// Measured is false when the size is not known (e.g. not scanned).
	Measured bool `json:"measured"`
}

// TierTotal sums findings per risk tier.
type TierTotal struct {
	Tier  safety.Tier `json:"tier"`
	Size  uint64      `json:"size_bytes"`
	Count int         `json:"count"`
}

// Item is one row in a findings table.
type Item struct {
	Path           string      `json:"path"`
	Size           uint64      `json:"size_bytes"`
	Tier           safety.Tier `json:"tier"`
	Category       string      `json:"category"`
	RuleID         string      `json:"rule_id,omitempty"`
	Modified       time.Time   `json:"modified"`
	Why            string      `json:"why"`
	Regenerate     string      `json:"regenerate,omitempty"`
	NativeClean    []string    `json:"native_clean,omitempty"`
	NativeOnly     bool        `json:"native_only,omitempty"`
	Override       string      `json:"override,omitempty"`
	Stale          bool        `json:"stale,omitempty"`
	LastActivity   time.Time   `json:"last_activity,omitempty"`
	ProjectRoot    string      `json:"project_root,omitempty"`
	FromLocation   bool        `json:"from_location,omitempty"`
	FromLargeFiles bool        `json:"from_large_files,omitempty"`
}

// Project groups stale artifacts by project root.
type Project struct {
	Root         string    `json:"root"`
	LastActivity time.Time `json:"last_activity"`
	Reclaimable  uint64    `json:"reclaimable_bytes"`
	Artifacts    []string  `json:"artifacts"`
}

// Step is a suggested next command.
type Step struct {
	Command string `json:"command"`
	Why     string `json:"why"`
}

// Options configures Build.
type Options struct {
	Home string
	Now  time.Time
	// TopN bounds the candidate list (default 20); other lists use smaller
	// fixed limits.
	TopN int
}

const (
	reviewLimit    = 15
	protectedLimit = 10
	// largeFileMin: unclassified files at least this big are listed for review.
	largeFileMin = 100_000_000
	// smallBucketShare: home folders below this share of the scan are merged
	// into "Your files: other folders".
	smallBucketShare = 0.005
)

// Build assembles the report from a saved scan. It is a pure function of
// its inputs and touches no files.
func Build(s *cache.Scan, o Options) *Report {
	if o.TopN <= 0 {
		o.TopN = 20
	}
	res := s.Result
	r := &Report{
		ScanRoot:     res.Root,
		CleanedItems: s.CleanedItems,
		CleanedBytes: s.CleanedBytes,
		ScannedAt:    res.FinishedAt,
		WholeDisk:    len(res.Walks) > 1 || res.Root == "/",
		UnitsNote:    UnitsNote,
		ClonesNote:   ClonesNote,
	}
	r.Categories = categories(s, o.Home, fsRoot(r))
	r.Tiers = TierTotals(s.Findings)
	r.Disk = diskOverview(s, r.WholeDisk, o.Home)
	r.SystemData = systemData(s, r)
	r.Candidates = candidates(s.Findings, o.TopN)
	r.StaleProjects, r.SmallStaleProjects = staleProjects(s.Findings)
	r.Review = review(s, o.Home)
	r.Protected = protected(s.Findings, r.Categories)
	r.NextSteps = nextSteps(r, s)
	return r
}

// ClonesNote explains the one known source of overcounting.
const ClonesNote = "APFS clones (e.g. Finder duplicates) are counted at full size for each copy, so totals can exceed real usage."

var allTiers = []safety.Tier{safety.TierSafe, safety.TierCaution, safety.TierReview, safety.TierProtected}

// TierTotals sums findings per tier, always listing all four tiers.
func TierTotals(fs []classifier.Finding) []TierTotal {
	out := make([]TierTotal, len(allTiers))
	idx := map[safety.Tier]int{}
	for i, t := range allTiers {
		out[i].Tier = t
		idx[t] = i
	}
	for _, f := range fs {
		if i, ok := idx[f.Tier]; ok {
			out[i].Size += f.Size
			out[i].Count++
		}
	}
	return out
}

// categories splits the scanned total into rule categories plus location
// buckets for everything no rule matched. The parts add up to the total.
func categories(s *cache.Scan, home, fsroot string) []Category {
	tree := s.Result.Tree
	sizes := map[string]uint64{}
	kinds := map[string]string{}
	add := func(name, kind string, n uint64) {
		sizes[name] += n
		kinds[name] = kind
	}

	dirFindings := map[string]bool{}
	for _, f := range s.Findings {
		add(f.Category, "rule", f.Size)
		if f.IsDir {
			dirFindings[strings.ToLower(f.Path)] = true
		}
	}

	// Bytes not under a finding, attributed to where they live. A node's own
	// bytes are its size minus its (kept) children's sizes; the tree may be
	// compacted, but sizes are always preserved in ancestors.
	seen := map[string]bool{}
	tree.Walk(func(p string, n *scanner.Node) bool {
		if dirFindings[strings.ToLower(p)] {
			seen[strings.ToLower(p)] = true
			// Findings nested inside this one are part of its node's size.
			prefix := strings.ToLower(p) + "/"
			for _, f := range s.Findings {
				if strings.HasPrefix(strings.ToLower(f.Path), prefix) {
					seen[strings.ToLower(f.Path)] = true
				}
			}
			return false
		}
		own := n.Size
		for _, c := range n.Children {
			own -= min(own, c.Size)
		}
		add(locationBucket(p, home, fsroot), "location", own)
		return true
	})
	// Findings not visited as tree nodes (files, or directories compacted
	// away) were counted in the own bytes of their deepest kept ancestor;
	// move them out of that ancestor's bucket.
	for _, f := range s.Findings {
		if seen[strings.ToLower(f.Path)] {
			continue
		}
		b := locationBucket(deepestNode(tree, f.Path), home, fsroot)
		sizes[b] -= min(sizes[b], f.Size)
	}

	total := tree.Size
	out := make([]Category, 0, len(sizes))
	var other uint64
	const otherFolders = "Your files: other folders"
	for name, n := range sizes {
		if n == 0 {
			continue
		}
		if name == otherFolders || kinds[name] == "location" && strings.HasPrefix(name, "Your files: ~/") && share(n, total) < smallBucketShare {
			other += n
			continue
		}
		out = append(out, Category{Name: name, Kind: kinds[name], Size: n, Share: share(n, total)})
	}
	if other > 0 {
		out = append(out, Category{Name: otherFolders, Kind: "location", Size: other, Share: share(other, total)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func share(n, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total)
}

// pathCount formats "1 path" / "1,240 paths".
func pathCount(n uint64) string {
	if n == 1 {
		return "1 path"
	}
	return Count(n) + " paths"
}

// tilde abbreviates the home directory to ~.
func tilde(p, home string) string {
	if home == "" || home == "/" {
		return p
	}
	if p == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(p, home+"/"); ok {
		return "~/" + rest
	}
	return p
}

// fsRoot is the filesystem root paths are relative to: the scan root for a
// whole-disk scan (normally "/"), otherwise "/".
func fsRoot(r *Report) string {
	if r.WholeDisk {
		return r.ScanRoot
	}
	return "/"
}

// locationBucket names where an unclassified path lives. System locations
// are recognised relative to fsroot.
func locationBucket(p, home, fsroot string) string {
	lp, lh := strings.ToLower(p), strings.ToLower(home)
	if home != "" && (lp == lh || strings.HasPrefix(lp, lh+"/")) {
		rel := strings.TrimPrefix(strings.TrimPrefix(p, home), "/")
		first, _, _ := strings.Cut(rel, "/")
		switch {
		case first == "":
			return "Your files: other folders" // files directly in home
		case strings.EqualFold(first, "Library"):
			return "App data: ~/Library (unclassified)"
		case strings.HasPrefix(first, "."):
			return "Tool data: ~/.* folders"
		default:
			return "Your files: ~/" + first
		}
	}
	if fsroot != "/" {
		lr := strings.ToLower(filepath.Clean(fsroot))
		if lp == lr {
			lp = "/"
		} else if rest, ok := strings.CutPrefix(lp, lr+"/"); ok {
			lp = "/" + rest
		}
	}
	comps := strings.Split(strings.Trim(lp, "/"), "/")
	switch {
	case comps[0] == "users":
		return "Other users"
	case comps[0] == "applications":
		return "Applications"
	case comps[0] == "library":
		return "Shared app data: /Library"
	case comps[0] == "opt", comps[0] == "usr" && len(comps) > 1 && comps[1] == "local":
		return "Homebrew, /usr/local & /opt"
	case comps[0] == "private":
		return "macOS: system data (/private)"
	case comps[0] == "system", comps[0] == "usr", comps[0] == "bin", comps[0] == "sbin":
		return "macOS: system files"
	case comps[0] == "":
		return "macOS: system files"
	default:
		return "Other"
	}
}

// deepestNode returns the path of the deepest node in tree that is p or an
// ancestor of p.
func deepestNode(tree *scanner.Node, p string) string {
	root := filepath.Clean(tree.Name)
	cur, curPath := tree, root
	rel, ok := strings.CutPrefix(filepath.Clean(p), strings.TrimSuffix(root, "/")+"/")
	if !ok {
		return curPath
	}
	for _, part := range strings.Split(rel, "/") {
		var next *scanner.Node
		for _, c := range cur.Children {
			if c.Name == part {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		cur, curPath = next, filepath.Join(curPath, part)
	}
	return curPath
}

func diskOverview(s *cache.Scan, whole bool, home string) *DiskOverview {
	if s.Disk == nil {
		return nil
	}
	d := &DiskOverview{
		Total:        s.Disk.Total,
		Used:         s.Disk.Used,
		Available:    s.Disk.Available,
		Scanned:      s.Result.Stats.Size,
		Inaccessible: s.Result.Stats.Inaccessible,
	}
	if c := s.Container; c != nil {
		d.Total, d.Used = c.Capacity, c.Used()
	}
	if !whole {
		d.Explanation = append(d.Explanation, fmt.Sprintf(
			"Only %s was scanned, so most of the used space lies outside it. Run 'sweep scan' with no path to measure the whole disk.", tilde(s.Result.Root, home)))
		return d
	}

	var others uint64
	if c := s.Container; c != nil {
		for _, v := range c.Volumes {
			if v.HasRole("System") || v.HasRole("Data") {
				continue
			}
			d.OtherVolumes = append(d.OtherVolumes, v)
			others += v.Used
		}
		sort.Slice(d.OtherVolumes, func(i, j int) bool { return d.OtherVolumes[i].Used > d.OtherVolumes[j].Used })
	}
	accounted := d.Scanned + others
	switch {
	case d.Used > accounted:
		d.Unaccounted = d.Used - accounted
	case accounted > d.Used:
		d.Overcounted = accounted - d.Used
	}

	if len(d.OtherVolumes) > 0 {
		d.Explanation = append(d.Explanation, "Other APFS volumes in the same container (Preboot, Recovery, VM swap, updates) share the disk but are not files you can browse; they are listed separately.")
	}
	if d.Unaccounted > 0 {
		e := "The rest is space the scan cannot see: local Time Machine snapshots, purgeable space macOS frees on demand, and APFS metadata"
		if n := len(s.Snapshots); n > 0 {
			e = fmt.Sprintf("The rest is space the scan cannot see: %d local Time Machine snapshots, purgeable space macOS frees on demand, and APFS metadata", n)
		}
		if d.Inaccessible > 0 {
			e += fmt.Sprintf(", plus %s that could not be read (grant Full Disk Access; see 'sweep doctor')", pathCount(d.Inaccessible))
		}
		d.Explanation = append(d.Explanation, e+".")
	}
	if d.Overcounted > 0 {
		d.Explanation = append(d.Explanation, "The scan found more than the disk reports as used: "+ClonesNote)
	}
	if s.Container == nil {
		d.Explanation = append(d.Explanation, "Per-volume usage was unavailable (diskutil failed), so other volumes are included in the unaccounted space.")
	}
	return d
}

// systemData decodes what macOS lumps into "System Data".
func systemData(s *cache.Scan, r *Report) []SystemItem {
	byRule := map[string]uint64{}
	byCategory := map[string]uint64{}
	var devCaches uint64
	for _, f := range s.Findings {
		byRule[f.RuleID] += f.Size
		byCategory[f.Category] += f.Size
		if strings.HasPrefix(f.Category, "Dev:") && f.ProjectRoot == "" {
			devCaches += f.Size
		}
	}
	sum := func(ids ...string) uint64 {
		var n uint64
		for _, id := range ids {
			n += byRule[id]
		}
		return n
	}
	volume := func(role string) (uint64, bool) {
		if s.Container == nil {
			return 0, false
		}
		var n uint64
		found := false
		for _, v := range s.Container.Volumes {
			if v.HasRole(role) {
				n += v.Used
				found = true
			}
		}
		return n, found
	}
	location := func(name string) uint64 {
		for _, c := range r.Categories {
			if c.Name == name {
				return c.Size
			}
		}
		return 0
	}

	items := []SystemItem{
		{Name: "App caches", Explanation: "Files apps keep to load faster; rebuilt as needed.", Size: byCategory["System: Caches"] + byCategory["App caches"], Measured: true},
		{Name: "Developer caches", Explanation: "Package and build caches (npm, Homebrew, Go, Xcode DerivedData, ...); re-downloaded or rebuilt on demand.", Size: devCaches + byRule["homebrew-cache"], Measured: true},
		{Name: "Logs and crash reports", Explanation: "Diagnostic logs; safe to remove.", Size: byCategory["System: Logs"], Measured: true},
		{Name: "Simulators and device support", Explanation: "iOS simulator devices and debug symbols copied from connected devices.", Size: sum("xcode-simulators", "xcode-device-support"), Measured: true},
		{Name: "Docker and virtual machines", Explanation: "Container images and VM disks; reclaim with the tool's own prune command.", Size: byCategory["Containers & VMs"], Measured: true},
		{Name: "iPhone/iPad backups", Explanation: "Device backups made by Finder; possibly your only copy.", Size: sum("ios-backups"), Measured: true},
		{Name: "Trash", Explanation: "Deleted files not yet emptied.", Size: sum("trash"), Measured: true},
		{Name: "Temporary files (/private/var/folders)", Explanation: "Per-user temp files and caches managed by macOS; a reboot clears much of it.", Size: sum("var-folders"), Measured: true},
		{Name: "Other app data in ~/Library", Explanation: "Settings, databases and support files of installed apps that no rule classifies.", Size: location("App data: ~/Library (unclassified)"), Measured: true},
	}
	if n, ok := volume("VM"); ok {
		items = append(items, SystemItem{Name: "Swap and sleepimage (VM volume)", Explanation: "Virtual memory managed by macOS; shrinks after a reboot.", Size: n + sum("vm-swap"), Measured: true})
	} else if n := sum("vm-swap"); n > 0 {
		items = append(items, SystemItem{Name: "Swap and sleepimage", Explanation: "Virtual memory managed by macOS; shrinks after a reboot.", Size: n, Measured: true})
	}
	var sysVols uint64
	found := false
	for _, role := range []string{"Preboot", "Recovery", "Update"} {
		if n, ok := volume(role); ok {
			sysVols += n
			found = true
		}
	}
	if found {
		items = append(items, SystemItem{Name: "macOS support volumes", Explanation: "Preboot, Recovery and pending-update volumes; managed by macOS.", Size: sysVols, Measured: true})
	}
	snapName, snapWhy := "Snapshots, purgeable and unreadable space", "Used space the scan cannot see (local Time Machine snapshots, purgeable files, unreadable folders)."
	if n := len(s.Snapshots); n > 0 {
		snapName = fmt.Sprintf("Time Machine local snapshots (%d), purgeable and unreadable space", n)
		snapWhy = "Space the scan cannot see. Snapshots are freed by macOS automatically when space runs low; 'sweep clean --snapshots' asks it to now."
		if d := s.Snapshots[0].Date; !d.IsZero() {
			snapWhy = fmt.Sprintf("Oldest snapshot: %s. ", d.Format("2006-01-02")) + snapWhy
		}
	}
	if r.Disk != nil && r.WholeDisk {
		items = append(items, SystemItem{Name: snapName, Explanation: snapWhy, Size: r.Disk.Unaccounted, Measured: true})
	} else {
		items = append(items, SystemItem{Name: snapName, Explanation: "Only measurable from a whole-disk scan. " + snapWhy, Measured: false})
	}

	out := items[:0]
	for _, it := range items {
		if it.Size > 0 || !it.Measured {
			out = append(out, it)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	return out
}

func itemFrom(f classifier.Finding) Item {
	why := f.Description
	if f.Override != "" {
		why = f.Override + ". " + why
	}
	return Item{
		Path: f.Path, Size: f.Size, Tier: f.Tier, Category: f.Category, RuleID: f.RuleID,
		Modified: f.Newest, Why: why, Regenerate: f.RegenerateHint, NativeClean: f.NativeClean,
		NativeOnly: f.NativeOnly, Override: f.Override, Stale: f.Stale, LastActivity: f.LastActivity,
		ProjectRoot: f.ProjectRoot,
	}
}

func candidates(fs []classifier.Finding, n int) []Item {
	out := []Item{}
	for _, f := range fs { // findings are sorted largest first
		if f.Tier.Deletable() && f.Size > 0 {
			out = append(out, itemFrom(f))
			if len(out) == n {
				break
			}
		}
	}
	return out
}

// staleProjectMin hides stale projects with almost nothing to reclaim.
const staleProjectMin = 1_000_000

func staleProjects(fs []classifier.Finding) ([]Project, int) {
	by := map[string]*Project{}
	var roots []string
	for _, f := range fs {
		if !f.Stale || f.ProjectRoot == "" || !f.Tier.Deletable() {
			continue
		}
		if _, ok := by[f.ProjectRoot]; !ok {
			by[f.ProjectRoot] = &Project{Root: f.ProjectRoot, LastActivity: f.LastActivity}
			roots = append(roots, f.ProjectRoot)
		}
	}
	// Group monorepo packages under the outermost stale project root.
	sort.Slice(roots, func(i, j int) bool { return len(roots[i]) < len(roots[j]) })
	owner := map[string]string{}
	for _, r := range roots {
		owner[r] = r
		for _, outer := range roots {
			if len(outer) < len(r) && strings.HasPrefix(strings.ToLower(r), strings.ToLower(outer)+"/") {
				owner[r] = owner[outer]
				break
			}
		}
	}
	counts := map[string]map[string]int{}
	for _, f := range fs {
		if !f.Stale || f.ProjectRoot == "" || !f.Tier.Deletable() {
			continue
		}
		root := owner[f.ProjectRoot]
		p := by[root]
		p.Reclaimable += f.Size
		if f.LastActivity.After(p.LastActivity) {
			p.LastActivity = f.LastActivity
		}
		if counts[root] == nil {
			counts[root] = map[string]int{}
		}
		counts[root][filepath.Base(f.Path)]++
	}
	var out []Project
	hidden := 0
	for root, names := range counts {
		p := by[root]
		if p.Reclaimable < staleProjectMin {
			hidden++
			continue
		}
		for name, n := range names {
			if n > 1 {
				name = fmt.Sprintf("%s ×%d", name, n)
			}
			p.Artifacts = append(p.Artifacts, name)
		}
		sort.Strings(p.Artifacts)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reclaimable != out[j].Reclaimable {
			return out[i].Reclaimable > out[j].Reclaimable
		}
		return out[i].Root < out[j].Root
	})
	return out, hidden
}

// review lists REVIEW findings plus large files no rule covers.
func review(s *cache.Scan, home string) []Item {
	out := []Item{}
	var dirs []string
	for _, f := range s.Findings {
		if f.IsDir {
			dirs = append(dirs, strings.ToLower(f.Path)+"/")
		}
		if f.Tier == safety.TierReview {
			out = append(out, itemFrom(f))
		}
	}
	findingPaths := map[string]bool{}
	for _, f := range s.Findings {
		findingPaths[strings.ToLower(f.Path)] = true
	}
	lh := strings.ToLower(home) + "/"
	for _, tf := range s.Result.TopFiles {
		lp := strings.ToLower(tf.Path)
		if tf.Size < largeFileMin || !strings.HasPrefix(lp, lh) || findingPaths[lp] || underAny(lp, dirs) {
			continue
		}
		cat, why := "Unclassified large file", "Large file no rule recognises; likely yours."
		switch rel := strings.TrimPrefix(lp, lh); {
		case strings.HasPrefix(rel, "library/"):
			cat, why = "App data: large file", "Large file inside an app's data in ~/Library; remove it from within the app."
		case strings.HasPrefix(rel, "."):
			cat, why = "Tool data: large file", "Large file inside a tool's hidden folder; remove it with that tool."
		}
		out = append(out, Item{
			Path: tf.Path, Size: tf.Size, Tier: safety.TierReview, Category: cat,
			Modified: tf.MTime, Why: why, FromLargeFiles: true,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	if len(out) > reviewLimit {
		out = out[:reviewLimit]
	}
	return out
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// protected lists the largest protected findings and the big system
// locations that are protected by default.
func protected(fs []classifier.Finding, cats []Category) []Item {
	out := []Item{}
	for _, f := range fs {
		if f.Tier == safety.TierProtected && f.Size > 0 {
			out = append(out, itemFrom(f))
		}
	}
	explain := map[string]string{
		"macOS: system files":           "The sealed macOS system and its support files.",
		"macOS: system data (/private)": "System databases, logs and temporary data managed by macOS.",
		"Applications":                  "Installed apps. Remove apps by dragging them to the Trash in Finder, not with sweep.",
		"Shared app data: /Library":     "Data and plug-ins shared by all users' apps.",
		"Homebrew, /usr/local & /opt":   "Command-line tools installed by Homebrew and others. Use 'brew cleanup' / 'brew uninstall'.",
	}
	for _, c := range cats {
		if why, ok := explain[c.Name]; ok && c.Size > 0 {
			out = append(out, Item{Path: c.Name, Size: c.Size, Tier: safety.TierProtected, Category: "Location", Why: why, FromLocation: true})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	if len(out) > protectedLimit {
		out = out[:protectedLimit]
	}
	return out
}

// manualCommand is a native command as a person would type it: sweep adds
// non-interactive flags only because it asks for confirmation itself.
func manualCommand(cmd []string) string {
	var out []string
	for _, a := range cmd {
		if a != "--force" && a != "--yes" {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

func nextSteps(r *Report, s *cache.Scan) []Step {
	var steps []Step
	tier := map[safety.Tier]TierTotal{}
	for _, t := range r.Tiers {
		tier[t.Tier] = t
	}
	if t := tier[safety.TierSafe]; t.Count > 0 {
		steps = append(steps, Step{"sweep clean --tier safe", fmt.Sprintf("preview removing %s of regenerable files (moved to the Trash)", Bytes(t.Size))})
	}
	if len(r.StaleProjects) > 0 {
		steps = append(steps, Step{"sweep clean --older-than 30d", fmt.Sprintf("preview cleaning only the %d stale projects' artifacts", len(r.StaleProjects))})
	}
	if t := tier[safety.TierCaution]; t.Count > 0 {
		steps = append(steps, Step{"sweep clean --tier caution", fmt.Sprintf("preview %s that is regenerable but slower to restore", Bytes(t.Size))})
	}
	seen := map[string]bool{}
	for _, f := range s.Findings {
		if f.NativeOnly && f.Size >= 50_000_000 && !seen[f.RuleID] {
			seen[f.RuleID] = true
			steps = append(steps, Step{manualCommand(f.NativeClean), fmt.Sprintf("reclaim space inside %s (%s on disk)", filepath.Base(f.Path), Bytes(f.Size))})
		}
	}
	if len(s.Snapshots) > 0 {
		steps = append(steps, Step{"sweep clean --snapshots --interactive", fmt.Sprintf("thin %d local Time Machine snapshots (tmutil), choosing what else to include", len(s.Snapshots))})
	}
	if s.Result.Stats.Inaccessible > 0 {
		steps = append(steps, Step{"sweep doctor", fmt.Sprintf("%s unreadable; grant Full Disk Access for complete numbers", pathCount(s.Result.Stats.Inaccessible))})
	}
	if !r.WholeDisk {
		steps = append(steps, Step{"sweep scan", "scan the whole disk to see everything, including System Data"})
	}
	steps = append(steps, Step{"sweep show <path>", "see why any path got its tier"})
	return steps
}
