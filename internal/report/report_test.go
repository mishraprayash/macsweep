package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

func TestReportPackageIsReadOnly(t *testing.T) {
	testutil.AssertReadOnlyPackage(t, ".")
}

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

// pipeline scans root with home's rules exactly as `sweep scan` does,
// including compacting the tree, and returns what would be saved.
func pipeline(t *testing.T, root, fsroot, home string) *cache.Scan {
	t.Helper()
	b, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.NewSet(rules.Options{Home: home, Rules: b, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	g, err := safety.NewGuard(home)
	if err != nil {
		t.Fatal(err)
	}
	cls := classifier.New(set, g, func() time.Time { return now })
	res, err := scanner.Scan(context.Background(), scanner.Options{Root: root, FSRoot: fsroot, Visit: cls.Visit})
	if err != nil {
		t.Fatal(err)
	}
	fs := cls.Findings(res)
	res.Tree.Compact(1_000_000)
	return &cache.Scan{Result: res, Findings: fs}
}

func homeTree() testutil.Tree {
	return testutil.Tree{
		// Stale JS project with artifacts above and below the 1 MB compaction threshold.
		"code/old/package.json":        testutil.File{Size: 10, MTime: days(200)},
		"code/old/src/a.js":            testutil.File{Size: 10, MTime: days(200)},
		"code/old/node_modules/x/x.js": testutil.File{Size: 3_000_000, MTime: days(1)},
		"code/old/coverage/lcov.info":  testutil.File{Size: 40_000, MTime: days(1)}, // compacted away
		// Active Rust project.
		"code/rs/Cargo.toml":       testutil.File{Size: 10, MTime: days(1)},
		"code/rs/target/debug/app": testutil.File{Size: 2_000_000},
		// Caches, logs, a venv (CAUTION), Docker (native only).
		"Library/Caches/com.example/blob":                                 testutil.File{Size: 1_500_000},
		"Library/Caches/tiny/blob":                                        testutil.File{Size: 5_000}, // compacted away
		"Library/Logs/app.log":                                            testutil.File{Size: 300_000},
		"code/ml/.venv/pyvenv.cfg":                                        testutil.File{Size: 10},
		"code/ml/.venv/lib/torch.so":                                      testutil.File{Size: 1_200_000},
		"Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw": testutil.File{Size: 1_100_000},
		"Library/Preferences/com.example.plist":                           testutil.File{Size: 2_000},
		// Review and protected.
		"Downloads/old-installer.dmg":        testutil.File{Size: 900_000, MTime: days(90)},
		"Movies/big.mov":                     testutil.File{Size: 1_000_000},
		"Library/Mobile Documents/doc.pages": testutil.File{Size: 1_300_000},
		".ssh/id_ed25519":                    testutil.File{Size: 10},
		".npm-ish/blob":                      testutil.File{Size: 50_000},
		"Documents/thesis.pdf":               testutil.File{Size: 2_500_000},
		"notes.txt":                          testutil.File{Size: 10},
	}
}

func TestCategoriesSumToScannedTotal(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, homeTree())
	scan := pipeline(t, s.Home, "/", s.Home)
	r := Build(scan, Options{Home: s.Home, Now: now})

	var sum uint64
	names := map[string]uint64{}
	for _, c := range r.Categories {
		sum += c.Size
		names[c.Name] = c.Size
	}
	if sum != scan.Result.Tree.Size {
		t.Fatalf("categories sum to %d, scanned %d; diff %d\n%+v", sum, scan.Result.Tree.Size, int64(scan.Result.Tree.Size)-int64(sum), r.Categories)
	}
	for _, want := range []string{"Dev: JavaScript", "Dev: Rust", "Dev: Python", "System: Caches", "System: Logs",
		"Containers & VMs", "Personal data", "User files: Downloads", "Your files: ~/Documents", "App data: ~/Library (unclassified)"} {
		if names[want] == 0 {
			t.Errorf("missing category %q in %v", want, names)
		}
	}
}

// buildDisk lays out a fake whole disk whose home is <disk>/Users/alice on
// the data volume.
func buildDisk(t *testing.T, disk string) string {
	tree := testutil.Tree{
		"usr/share/firmlinks":      testutil.File{Content: []byte("/Users\tUsers\n/Applications\tApplications\n/Library\tLibrary\n/private\tprivate\n")},
		"usr/bin/tool":             testutil.File{Size: 1_500_000},
		"System/Library/Kernels/k": testutil.File{Size: 2_000_000},
		"System/Volumes/Data/Applications/App.app/Contents/MacOS/App": testutil.File{Size: 3_000_000},
		"System/Volumes/Data/Library/Shared/blob":                     testutil.File{Size: 1_200_000},
		"System/Volumes/Data/private/var/log/system.log":              testutil.File{Size: 400_000},
		"System/Volumes/Data/private/var/folders/xx/tmp":              testutil.File{Size: 1_100_000},
		"System/Volumes/Data/Users/bob/file":                          testutil.File{Size: 1_000_000},
		// Stand-ins for the firmlinks, so user-facing paths resolve (markers).
		"Users":        testutil.Symlink{Target: "System/Volumes/Data/Users"},
		"Applications": testutil.Symlink{Target: "System/Volumes/Data/Applications"},
		"Library":      testutil.Symlink{Target: "System/Volumes/Data/Library"},
		"private":      testutil.Symlink{Target: "System/Volumes/Data/private"},
	}
	for p, e := range homeTree() {
		tree["System/Volumes/Data/Users/alice/"+p] = e
	}
	testutil.Build(t, disk, tree)
	return filepath.Join(disk, "Users", "alice")
}

func TestWholeDiskReport(t *testing.T) {
	s := testutil.NewSandbox(t)
	home := buildDisk(t, s.Tree)
	scan := pipeline(t, s.Tree, s.Tree, home)
	if len(scan.Result.Walks) != 2 {
		t.Fatalf("expected a whole-disk scan, walks = %+v", scan.Result.Walks)
	}
	scanned := scan.Result.Stats.Size
	scan.Container = &macos.APFSContainer{Capacity: 100e9, Free: 100e9 - (scanned + 9e9 + 5e9), Volumes: []macos.APFSVolume{
		{Name: "Macintosh HD", Roles: []string{"System"}, Used: 1e9},
		{Name: "Data", Roles: []string{"Data"}, Used: scanned + 5e9},
		{Name: "Preboot", Roles: []string{"Preboot"}, Used: 6e9},
		{Name: "VM", Roles: []string{"VM"}, Used: 3e9},
	}}
	scan.Disk = &macos.DiskUsage{Total: 100e9, Used: scan.Container.Used(), Available: 1e9}
	r := Build(scan, Options{Home: home, Now: now})

	var sum uint64
	names := map[string]bool{}
	for _, c := range r.Categories {
		sum += c.Size
		names[c.Name] = true
	}
	if sum != scanned {
		t.Errorf("categories sum %d != scanned %d", sum, scanned)
	}
	for _, want := range []string{"macOS: system files", "Applications", "Shared app data: /Library", "Other users", "macOS: system data (/private)"} {
		if !names[want] {
			t.Errorf("missing category %q", want)
		}
	}

	d := r.Disk
	if d == nil || !r.WholeDisk {
		t.Fatal("no disk overview for whole-disk scan")
	}
	if d.Used != scanned+14e9 || d.Scanned != scanned || len(d.OtherVolumes) != 2 || d.Unaccounted != 5e9 {
		t.Errorf("disk overview = %+v (scanned %d)", d, scanned)
	}
	if d.OtherVolumes[0].Name != "Preboot" {
		t.Errorf("other volumes not sorted: %+v", d.OtherVolumes)
	}

	sys := map[string]uint64{}
	for _, it := range r.SystemData {
		sys[it.Name] = it.Size
	}
	if sys["Swap and sleepimage (VM volume)"] != 3e9 || sys["macOS support volumes"] != 6e9 ||
		sys["Snapshots, purgeable and unreadable space"] != 5e9 {
		t.Errorf("system data = %v", sys)
	}

	// Overcount: the scan found more than the disk reports (clones).
	scan.Container.Free = scan.Container.Capacity - scanned/2
	r = Build(scan, Options{Home: home, Now: now})
	if r.Disk.Overcounted == 0 || r.Disk.Unaccounted != 0 || !strings.Contains(strings.Join(r.Disk.Explanation, " "), "clones") {
		t.Errorf("overcount not explained: %+v", r.Disk)
	}
}

func TestFindingSections(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, homeTree())
	scan := pipeline(t, s.Home, "/", s.Home)
	scan.Disk = &macos.DiskUsage{Total: 1e12, Used: 5e11, Available: 5e11}
	r := Build(scan, Options{Home: s.Home, Now: now, TopN: 3})

	if r.WholeDisk || r.Disk == nil || !strings.Contains(r.Disk.Explanation[0], "Only") {
		t.Errorf("partial scan overview = %+v", r.Disk)
	}
	if len(r.Candidates) != 3 {
		t.Fatalf("candidates = %d, want TopN=3", len(r.Candidates))
	}
	for i, c := range r.Candidates {
		if !c.Tier.Deletable() {
			t.Errorf("candidate %s has tier %v", c.Path, c.Tier)
		}
		if i > 0 && c.Size > r.Candidates[i-1].Size {
			t.Error("candidates not sorted by size")
		}
	}

	if len(r.StaleProjects) != 1 || r.StaleProjects[0].Root != filepath.Join(s.Home, "code/old") {
		t.Fatalf("stale projects = %+v", r.StaleProjects)
	}
	sp := r.StaleProjects[0]
	if strings.Join(sp.Artifacts, ",") != "coverage,node_modules" || sp.Reclaimable < 3_000_000 || !sp.LastActivity.Equal(days(200)) {
		t.Errorf("stale project = %+v", sp)
	}

	review := map[string]Item{}
	for _, it := range r.Review {
		review[strings.TrimPrefix(it.Path, s.Home+"/")] = it
		if it.Tier != safety.TierReview {
			t.Errorf("review item %s has tier %v", it.Path, it.Tier)
		}
	}
	if _, ok := review["Downloads/old-installer.dmg"]; !ok {
		t.Errorf("old download missing from review: %v", review)
	}

	prot := map[string]Item{}
	for _, it := range r.Protected {
		prot[it.Path] = it
		if it.Tier != safety.TierProtected {
			t.Errorf("protected item %s has tier %v", it.Path, it.Tier)
		}
	}
	if _, ok := prot[filepath.Join(s.Home, "Library/Mobile Documents")]; !ok {
		t.Errorf("iCloud Drive missing from protected: %v", prot)
	}

	cmds := map[string]bool{}
	for _, st := range r.NextSteps {
		cmds[st.Command] = true
	}
	for _, want := range []string{"sweep clean --tier safe --dry-run", "sweep clean --tier caution --dry-run", "sweep clean --older-than 30d --dry-run", "sweep scan", "sweep explain <path>"} {
		if !cmds[want] {
			t.Errorf("next steps missing %q: %v", want, cmds)
		}
	}
}

func TestLargeUnclassifiedFilesInReview(t *testing.T) {
	scan := &cache.Scan{
		Result: &scanner.Result{
			Root: "/Users/u", Tree: &scanner.Node{Name: "/Users/u", Size: 3e9},
			TopFiles: []scanner.FileEntry{
				{Path: "/Users/u/Movies/raw.braw", Size: 2e9},
				{Path: "/Users/u/code/web/node_modules/huge.bin", Size: 5e8}, // inside a finding
				{Path: "/Users/u/small.bin", Size: 1e6},                      // too small
				{Path: "/opt/big.bin", Size: 9e9},                            // outside home
			},
		},
		Findings: []classifier.Finding{{Path: "/Users/u/code/web/node_modules", IsDir: true, Tier: safety.TierSafe, Size: 6e8}},
	}
	r := Build(scan, Options{Home: "/Users/u", Now: now})
	if len(r.Review) != 1 || r.Review[0].Path != "/Users/u/Movies/raw.braw" || !r.Review[0].FromLargeFiles {
		t.Errorf("review = %+v", r.Review)
	}
}

func TestLocationBucket(t *testing.T) {
	h := "/Users/u"
	for p, want := range map[string]string{
		"/Users/u":                     "Your files: other folders",
		"/Users/u/Documents":           "Your files: ~/Documents",
		"/Users/u/Documents/a/b":       "Your files: ~/Documents",
		"/Users/u/my.project/src":      "Your files: ~/my.project",
		"/Users/u/Library/Preferences": "App data: ~/Library (unclassified)",
		"/Users/u/.cache/x":            "Tool data: ~/.* folders",
		"/Users/other/x":               "Other users",
		"/Users":                       "Other users",
		"/Applications/X.app":          "Applications",
		"/Library/Fonts":               "Shared app data: /Library",
		"/usr/local/bin":               "Homebrew, /usr/local & /opt",
		"/opt/homebrew":                "Homebrew, /usr/local & /opt",
		"/usr/lib":                     "macOS: system files",
		"/System/Library":              "macOS: system files",
		"/private/var/db":              "macOS: system data (/private)",
		"/":                            "macOS: system files",
		"/cores":                       "Other",
	} {
		if got := locationBucket(p, h, "/"); got != want {
			t.Errorf("locationBucket(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestBar(t *testing.T) {
	for _, tt := range []struct {
		frac  float64
		width int
		want  string
	}{
		{0, 10, ""},
		{1, 4, "████"},
		{0.5, 4, "██"},
		{0.0001, 10, "▏"},
		{0.53125, 4, "██▏"},
		{0.999, 4, "████"},
	} {
		if got := bar(tt.frac, tt.width); got != tt.want {
			t.Errorf("bar(%v, %d) = %q, want %q", tt.frac, tt.width, got, tt.want)
		}
	}
}

func TestRenderText(t *testing.T) {
	color.NoColor = true
	s := testutil.NewSandbox(t)
	home := buildDisk(t, s.Tree)
	scan := pipeline(t, s.Tree, s.Tree, home)
	scan.Container = &macos.APFSContainer{Capacity: 100e9, Free: 50e9, Volumes: []macos.APFSVolume{
		{Name: "Data", Roles: []string{"Data"}, Used: 40e9}, {Name: "VM", Roles: []string{"VM"}, Used: 1e9},
	}}
	scan.Disk = &macos.DiskUsage{Total: 100e9, Used: 50e9, Available: 49e9}
	r := Build(scan, Options{Home: home, Now: now})

	var buf bytes.Buffer
	if err := RenderText(&buf, r, TextOptions{Home: home, Now: now, Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	last := -1
	for _, h := range []string{"1. Disk overview", "2. Where your space is going", `3. "System Data" decoded`,
		"4. Reclaimable space", "5. Top", "6. Stale projects", "7. Largest items needing your judgment",
		"8. Protected (for your information)", "9. Next steps"} {
		i := strings.Index(out, h)
		if i < 0 || i < last {
			t.Errorf("section %q missing or out of order", h)
		}
		last = i
	}
	for _, want := range []string{"Unaccounted", "Other volumes", "█", "SAFE", "PROTECTED", "not deletable",
		"~/code/old/node_modules", "stale: no activity since", "Regenerate:", "base-10", "APFS clones", "sweep clean --tier safe --dry-run"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q", want)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, s.Tree) {
			continue // the temp-dir root is long; real roots are not
		}
		if n := len([]rune(line)); n > 100 {
			t.Errorf("line too long (%d): %q", n, line)
		}
	}

	// JSON carries the same data.
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Categories) != len(r.Categories) || len(back.Candidates) != len(r.Candidates) || back.Tiers[0].Tier != safety.TierSafe {
		t.Error("JSON round trip lost data")
	}
}

func TestEmptyScan(t *testing.T) {
	scan := &cache.Scan{Result: &scanner.Result{Root: "/x", Tree: &scanner.Node{Name: "/x"}}}
	r := Build(scan, Options{Home: "/Users/u", Now: now})
	var buf bytes.Buffer
	if err := RenderText(&buf, r, TextOptions{Home: "/Users/u", Now: now}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Disk totals were not recorded", "No SAFE or CAUTION findings", "No stale projects"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("empty report missing %q", want)
		}
	}
}

// TestCandidatesAreExactlyTheDeletableFindings: with no limit in the way,
// the candidate list is every SAFE/CAUTION finding and nothing else.
func TestCandidatesAreExactlyTheDeletableFindings(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, homeTree())
	scan := pipeline(t, s.Home, "/", s.Home)
	r := Build(scan, Options{Home: s.Home, Now: now, TopN: 1000})
	want := 0
	for _, f := range scan.Findings {
		if f.Tier.Deletable() && f.Size > 0 {
			want++
		}
	}
	if len(r.Candidates) != want {
		t.Errorf("%d candidates, want %d deletable findings", len(r.Candidates), want)
	}
	for _, c := range r.Candidates {
		if !c.Tier.Deletable() {
			t.Errorf("candidate %s has non-deletable tier %v", c.Path, c.Tier)
		}
	}
}

func TestCategoryNamesUnique(t *testing.T) {
	s := testutil.NewSandbox(t)
	tree := homeTree()
	for i := 0; i < 5; i++ { // several tiny home folders that get merged
		tree[fmt.Sprintf("tiny%d/f", i)] = testutil.File{Size: 10}
	}
	testutil.Build(t, s.Home, tree)
	r := Build(pipeline(t, s.Home, "/", s.Home), Options{Home: s.Home, Now: now})
	seen := map[string]bool{}
	for _, c := range r.Categories {
		if seen[c.Name] {
			t.Errorf("duplicate category %q", c.Name)
		}
		seen[c.Name] = true
	}
}

func TestNativeNextStepsOnlyWhenWorthIt(t *testing.T) {
	mk := func(size uint64) *Report {
		return Build(&cache.Scan{
			Result: &scanner.Result{Root: "/", Tree: &scanner.Node{Name: "/", Size: size}},
			Findings: []classifier.Finding{{Path: "/Users/u/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
				RuleID: "docker-desktop-disk", Tier: safety.TierCaution, Size: size, NativeOnly: true,
				NativeClean: []string{"docker", "system", "prune", "--force"}}},
		}, Options{Home: "/Users/u", Now: now})
	}
	has := func(r *Report) bool {
		for _, s := range r.NextSteps {
			if s.Command == "docker system prune" { // --force dropped for a manual command
				return true
			}
		}
		return false
	}
	if has(mk(4_000)) || !has(mk(7e9)) {
		t.Error("docker suggestion should appear only for a sizeable Docker disk")
	}
}

// TestNestedFindingsCountedOnce: an old Downloads folder containing a
// project keeps the project's artifacts as their own findings, and the
// folder's finding covers only the rest.
func TestNestedFindingsCountedOnce(t *testing.T) {
	s := testutil.NewSandbox(t)
	old := days(90)
	testutil.Build(t, s.Home, testutil.Tree{
		"Downloads/study/notes.pdf":                testutil.File{Size: 1_500_000, MTime: old},
		"Downloads/study/proj/package.json":        testutil.File{Size: 10, MTime: old},
		"Downloads/study/proj/node_modules/x/x.js": testutil.File{Size: 2_000_000, MTime: old},
	})
	scan := pipeline(t, s.Home, "/", s.Home)
	var outer, inner *classifier.Finding
	for i := range scan.Findings {
		switch rel := strings.TrimPrefix(scan.Findings[i].Path, s.Home+"/"); rel {
		case "Downloads/study":
			outer = &scan.Findings[i]
		case "Downloads/study/proj/node_modules":
			inner = &scan.Findings[i]
		}
	}
	if outer == nil || inner == nil {
		t.Fatalf("findings = %+v", scan.Findings)
	}
	if inner.NestedIn != outer.Path || inner.Tier != safety.TierSafe || outer.Tier != safety.TierReview {
		t.Errorf("inner %+v outer %+v", inner, outer)
	}
	if outer.Size >= 3_000_000 || outer.Size < 1_500_000 {
		t.Errorf("outer size %d should exclude node_modules", outer.Size)
	}
	r := Build(scan, Options{Home: s.Home, Now: now})
	var sum uint64
	for _, c := range r.Categories {
		sum += c.Size
	}
	if sum != scan.Result.Tree.Size {
		t.Errorf("categories sum %d != scanned %d", sum, scan.Result.Tree.Size)
	}
}

func TestStaleProjectsGrouping(t *testing.T) {
	f := func(path, root string, size uint64, last time.Time) classifier.Finding {
		return classifier.Finding{Path: path, ProjectRoot: root, Size: size, Stale: true, LastActivity: last, Tier: safety.TierSafe}
	}
	fs := []classifier.Finding{
		f("/u/mono/node_modules", "/u/mono", 5e6, days(100)),
		f("/u/mono/packages/a/dist", "/u/mono/packages/a", 1e6, days(90)),
		f("/u/mono/packages/b/dist", "/u/mono/packages/b", 1e6, days(120)),
		f("/u/py/a/__pycache__", "/u/py", 1e6, days(50)),
		f("/u/py/b/__pycache__", "/u/py", 1e6, days(50)),
		f("/u/tiny/dist", "/u/tiny", 1000, days(50)),
	}
	got, hidden := staleProjects(fs)
	if hidden != 1 || len(got) != 2 {
		t.Fatalf("got %+v hidden %d", got, hidden)
	}
	if got[0].Root != "/u/mono" || got[0].Reclaimable != 7e6 || !got[0].LastActivity.Equal(days(90)) ||
		strings.Join(got[0].Artifacts, ",") != "dist ×2,node_modules" {
		t.Errorf("monorepo = %+v", got[0])
	}
	if strings.Join(got[1].Artifacts, ",") != "__pycache__ ×2" {
		t.Errorf("py = %+v", got[1])
	}
}
