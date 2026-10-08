package classifier

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

func TestClassifierPackageIsReadOnly(t *testing.T) {
	testutil.AssertReadOnlyPackage(t, ".")
}

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type env struct {
	s   *testutil.Sandbox
	cls *Classifier
	set *rules.Set
}

func newEnv(t *testing.T, cfg *rules.UserConfig) *env {
	t.Helper()
	s := testutil.NewSandbox(t)
	b, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var excludes []string
	if cfg != nil {
		b = append(b, cfg.Rules...)
		excludes = cfg.Exclude
	}
	set, err := rules.NewSet(rules.Options{Home: s.Home, Rules: b, Excludes: excludes, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	g, err := safety.NewGuard(s.Home)
	if err != nil {
		t.Fatal(err)
	}
	return &env{s: s, cls: New(set, g, func() time.Time { return now }), set: set}
}

func (e *env) scan(t *testing.T) (*scanner.Result, []Finding) {
	t.Helper()
	res, err := scanner.Scan(context.Background(), scanner.Options{Root: e.s.Home, Visit: e.cls.Visit})
	if err != nil {
		t.Fatal(err)
	}
	return res, e.cls.Findings(res)
}

func byPath(fs []Finding, home string) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[strings.TrimPrefix(f.Path, home+"/")] = f
	}
	return m
}

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

func TestFindingsEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	testutil.Build(t, e.s.Home, testutil.Tree{
		"code/web/package.json":                  testutil.File{Size: 10},
		"code/web/node_modules/react/index.js":   testutil.File{Size: 2_000_000},
		"code/web/node_modules/a/node_modules/b": testutil.File{Size: 1}, // nested: not separate
		"code/web/node_modules/c/__pycache__/x":  testutil.File{Size: 1}, // inside pruned dir
		"Library/Caches/com.example/blob":        testutil.File{Size: 300_000},
		"Library/Caches/go-build/aa":             testutil.File{Size: 100_000},
		"Library/Logs/sweep/history.jsonl":       testutil.File{Size: 10}, // protected by the safety layer
		"Movies/trip.mov":                        testutil.Sparse{Size: 600_000_000},
		"Documents/thesis.pdf":                   testutil.File{Size: 10},
	})
	before := testutil.Snapshot(t, e.s.Home)
	res, fs := e.scan(t)
	testutil.AssertUnchanged(t, e.s.Home, before)

	got := byPath(fs, e.s.Home)
	want := map[string]struct {
		rule string
		tier safety.Tier
	}{
		"code/web/node_modules":      {"node-modules", safety.TierSafe},
		"Library/Caches/com.example": {"user-app-caches", safety.TierSafe},
		"Library/Caches/go-build":    {"go-build-cache", safety.TierSafe},
		"Library/Logs/sweep":         {"user-logs", safety.TierProtected},
	}
	for p, w := range want {
		f, ok := got[p]
		if !ok {
			t.Errorf("missing finding %s (have %v)", p, keys(got))
			continue
		}
		if f.RuleID != w.rule || f.Tier != w.tier {
			t.Errorf("%s: rule=%s tier=%v, want %s %v", p, f.RuleID, f.Tier, w.rule, w.tier)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings = %v, want exactly %v", keys(got), want)
	}
	// Sparse .mov: 600 MB apparent but tiny on disk, so large-media must not fire.
	if _, ok := got["Movies/trip.mov"]; ok {
		t.Error("sparse file matched large-media by apparent size")
	}

	nm := got["code/web/node_modules"]
	if nm.Size < 2_000_000 || nm.Files != 3 || !nm.IsDir || nm.Ino == 0 || nm.ProjectRoot != filepath.Join(e.s.Home, "code/web") {
		t.Errorf("node_modules finding = %+v", nm)
	}
	sw := got["Library/Logs/sweep"]
	if sw.RuleTier != safety.TierSafe || !strings.Contains(sw.Override, "audit log") {
		t.Errorf("audit log override = %+v", sw)
	}
	if fs[0].Size < fs[len(fs)-1].Size {
		t.Error("findings not sorted largest first")
	}
	if res.Tree.Find(filepath.Join(e.s.Home, "code/web/node_modules/react")) != nil {
		t.Error("matched directory was not pruned")
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSafetyLayerWinsOverUserRules: no user rule or tier can make a
// protected path deletable.
func TestSafetyLayerWinsOverUserRules(t *testing.T) {
	var userRules []*rules.Rule
	targets := []string{"~/.ssh", "~/Library/Keychains", "~/.aws", "~/Library/Mobile Documents", "~/code/app/.git", "~/code/app/.env"}
	for i, p := range targets {
		userRules = append(userRules, &rules.Rule{
			ID: fmt.Sprintf("evil-%d", i), Category: "Evil", Tier: safety.TierSafe, Description: "d",
			Source: "user.yaml", User: true, Match: rules.Match{Path: rules.StringList{p}},
		})
	}
	userRules = append(userRules, &rules.Rule{
		ID: "evil-glob", Category: "Evil", Tier: safety.TierSafe, Description: "d", Source: "user.yaml", User: true,
		Match: rules.Match{Glob: rules.StringList{"~/**/.git"}},
	})
	e := newEnv(t, &rules.UserConfig{Rules: userRules})
	testutil.Build(t, e.s.Home, testutil.Tree{
		".ssh/id_ed25519":                     testutil.File{Size: 10},
		"Library/Keychains/login.keychain-db": testutil.File{Size: 10},
		".aws/credentials":                    testutil.File{Size: 10},
		"Library/Mobile Documents/doc.pages":  testutil.File{Size: 10},
		"code/app/.git/HEAD":                  testutil.File{Size: 10},
		"code/app/.env":                       testutil.File{Size: 10},
		"code/other/.git/HEAD":                testutil.File{Size: 10},
	})
	_, fs := e.scan(t)
	if len(fs) < len(targets)+1 {
		t.Fatalf("expected every evil rule to match, got %d findings", len(fs))
	}
	for _, f := range fs {
		if f.RuleTier == safety.TierSafe && strings.HasPrefix(f.RuleID, "evil") && f.Tier != safety.TierProtected {
			t.Errorf("%s: tier %v, want PROTECTED (override %q)", f.Path, f.Tier, f.Override)
		}
		if f.Tier.Deletable() && strings.HasPrefix(f.RuleID, "evil") {
			t.Errorf("protected path %s is deletable", f.Path)
		}
	}
}

func TestExclusionsOnlyTighten(t *testing.T) {
	e := newEnv(t, &rules.UserConfig{Exclude: []string{"~/code/keep/**", "~/Library/Caches/com.precious"}})
	testutil.Build(t, e.s.Home, testutil.Tree{
		"code/keep/package.json":        testutil.File{Size: 1},
		"code/keep/node_modules/x":      testutil.File{Size: 1},
		"code/other/package.json":       testutil.File{Size: 1},
		"code/other/node_modules/x":     testutil.File{Size: 1},
		"Library/Caches/com.precious/x": testutil.File{Size: 1},
		".Trash/old":                    testutil.File{Size: 1},
	})
	_, fs := e.scan(t)
	got := byPath(fs, e.s.Home)
	for p, want := range map[string]safety.Tier{
		"code/keep/node_modules":      safety.TierReview,
		"Library/Caches/com.precious": safety.TierReview,
		"code/other/node_modules":     safety.TierSafe,
	} {
		f, ok := got[p]
		if !ok || f.Tier != want {
			t.Errorf("%s: tier %v (ok=%v), want %v", p, f.Tier, ok, want)
		}
		if want == safety.TierReview && f.Override != "excluded by your config" {
			t.Errorf("%s: override %q", p, f.Override)
		}
	}
}

func TestStaleness(t *testing.T) {
	e := newEnv(t, nil)
	testutil.Build(t, e.s.Home, testutil.Tree{
		// Source untouched for 200 days; node_modules reinstalled recently.
		"code/old/package.json":        testutil.File{Size: 1, MTime: days(200)},
		"code/old/src/index.js":        testutil.File{Size: 1, MTime: days(210)},
		"code/old/node_modules/x/a.js": testutil.File{Size: 1, MTime: days(1)},
		"code/old/dist/bundle.js":      testutil.File{Size: 1, MTime: days(2)},
		// Recently edited source.
		"code/fresh/package.json":        testutil.File{Size: 1, MTime: days(300)},
		"code/fresh/src/index.js":        testutil.File{Size: 1, MTime: days(3)},
		"code/fresh/node_modules/x/a.js": testutil.File{Size: 1, MTime: days(300)},
		// Old files, but a recent git commit.
		"code/git/Cargo.toml":     testutil.File{Size: 1, MTime: days(400)},
		"code/git/target/debug/x": testutil.File{Size: 1, MTime: days(400)},
		"code/git/.git/logs/HEAD": testutil.File{
			Content: []byte(fmt.Sprintf("0000 1111 A <a@b> %d +0000\tcommit: one\n0000 2222 A <a@b> %d +0000\tcommit: two\n", days(500).Unix(), days(5).Unix())),
			MTime:   days(400),
		},
	})
	_, fs := e.scan(t)
	got := byPath(fs, e.s.Home)

	old := got["code/old/node_modules"]
	if !old.Stale || !old.LastActivity.Equal(days(200)) {
		t.Errorf("old project: stale=%v last=%v, want stale with last activity %v (artifacts ignored)", old.Stale, old.LastActivity, days(200))
	}
	if d := got["code/old/dist"]; !d.Stale || !d.LastActivity.Equal(old.LastActivity) {
		t.Errorf("dist in the same project: %+v", d)
	}
	if fresh := got["code/fresh/node_modules"]; fresh.Stale || !fresh.LastActivity.Equal(days(3)) {
		t.Errorf("fresh project: stale=%v last=%v", fresh.Stale, fresh.LastActivity)
	}
	if g := got["code/git/target"]; g.Stale || g.LastActivity.Unix() != days(5).Unix() {
		t.Errorf("git project: stale=%v last=%v, want last commit %v", g.Stale, g.LastActivity, days(5))
	}
}

func TestDeferredSizeAgeForDirectories(t *testing.T) {
	e := newEnv(t, nil)
	testutil.Build(t, e.s.Home, testutil.Tree{
		"Downloads/old-folder/a":   testutil.File{Size: 1, MTime: days(60)},
		"Downloads/old-folder":     testutil.Dir{MTime: days(60)},
		"Downloads/new-folder/a":   testutil.File{Size: 1, MTime: days(1)},
		"Downloads/old-file.zip":   testutil.File{Size: 1, MTime: days(90)},
		"Downloads/fresh-file.txt": testutil.File{Size: 1, MTime: days(1)},
	})
	_, fs := e.scan(t)
	got := byPath(fs, e.s.Home)
	if _, ok := got["Downloads/old-folder"]; !ok {
		t.Error("old folder in Downloads not flagged")
	}
	if _, ok := got["Downloads/old-file.zip"]; !ok {
		t.Error("old file in Downloads not flagged")
	}
	for _, p := range []string{"Downloads/new-folder", "Downloads/fresh-file.txt"} {
		if _, ok := got[p]; ok {
			t.Errorf("recent %s flagged", p)
		}
	}
}

func TestDefaultTier(t *testing.T) {
	e := newEnv(t, nil)
	h := e.s.Home
	for p, want := range map[string]safety.Tier{
		h:                              safety.TierReview,
		h + "/Documents/x":             safety.TierReview,
		"/Library/Application Support": safety.TierProtected,
		h + "x/other":                  safety.TierProtected,
	} {
		if got := e.cls.DefaultTier(p); got != want {
			t.Errorf("DefaultTier(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestParseReflogTime(t *testing.T) {
	ts := parseReflogTime("abc def Jane Doe <j@x.org> 1700000000 +0100\tcommit: msg with 123 numbers")
	if ts.Unix() != 1700000000 {
		t.Errorf("got %v", ts)
	}
	for _, bad := range []string{"", "garbage", "a b c d notanumber +0000\tx"} {
		if !parseReflogTime(bad).IsZero() {
			t.Errorf("parseReflogTime(%q) should be zero", bad)
		}
	}
}

func TestExplain(t *testing.T) {
	e := newEnv(t, nil)
	h := e.s.Home
	testutil.Build(t, h, testutil.Tree{
		"code/web/package.json":                testutil.File{Size: 1},
		"code/web/node_modules/react/index.js": testutil.File{Size: 2_000_000},
		"Documents/notes.txt":                  testutil.File{Size: 5},
		".ssh/id_ed25519":                      testutil.File{Size: 5},
		"Library/Logs/sweep/history.jsonl":     testutil.File{Size: 5},
		"Downloads/some-folder/x":              testutil.File{Size: 5},
	})
	res, fs := e.scan(t)
	data := &ScanData{Result: res, Findings: fs}

	nm := e.cls.Explain(filepath.Join(h, "code/web/node_modules"), data)
	if nm.RuleID != "node-modules" || nm.Tier != safety.TierSafe || !nm.SizeKnown || nm.Size < 2_000_000 || nm.Unclassified {
		t.Errorf("node_modules: %+v", nm)
	}

	inner := e.cls.Explain(filepath.Join(h, "code/web/node_modules/react/index.js"), data)
	if inner.RuleID != "node-modules" || inner.MatchedPath != filepath.Join(h, "code/web/node_modules") {
		t.Errorf("file inside node_modules: %+v", inner)
	}

	doc := e.cls.Explain(filepath.Join(h, "Documents/notes.txt"), data)
	if !doc.Unclassified || doc.Tier != safety.TierReview {
		t.Errorf("unclassified doc: %+v", doc)
	}

	key := e.cls.Explain(filepath.Join(h, ".ssh/id_ed25519"), data)
	if key.Tier != safety.TierProtected || !strings.Contains(key.Override, "SSH") {
		t.Errorf("ssh key: %+v", key)
	}

	// A path inside a matched-but-protected ancestor inherits the protection.
	log := e.cls.Explain(filepath.Join(h, "Library/Logs/sweep/history.jsonl"), data)
	if log.Tier != safety.TierProtected || log.RuleID != "user-logs" {
		t.Errorf("audit log file: %+v", log)
	}

	missing := e.cls.Explain(filepath.Join(h, "code/ghost/node_modules"), nil)
	if missing.Exists || !missing.Unclassified {
		t.Errorf("missing path: %+v", missing)
	}

	// Without scan data, deferred conditions are reported as pending.
	pending := e.cls.Explain(filepath.Join(h, "Downloads/some-folder"), nil)
	if !pending.IsDir {
		t.Fatal("fixture folder missing")
	}
	if pending.RuleID != "old-downloads" || pending.Pending == "" {
		t.Errorf("pending: %+v", pending)
	}
}

// TestExplainOutermostMatchWins mirrors the scanner: once a directory
// matches, everything inside it belongs to that match, even if an inner path
// would match another rule on its own.
func TestExplainOutermostMatchWins(t *testing.T) {
	e := newEnv(t, nil)
	h := e.s.Home
	testutil.Build(t, h, testutil.Tree{
		"code/web/package.json":                  testutil.File{Size: 1},
		"code/web/node_modules/pkg/package.json": testutil.File{Size: 1},
		"code/web/node_modules/pkg/dist/i.js":    testutil.File{Size: 1},
	})
	got := e.cls.Explain(filepath.Join(h, "code/web/node_modules/pkg/dist"), nil)
	if got.RuleID != "node-modules" || got.MatchedPath != filepath.Join(h, "code/web/node_modules") {
		t.Errorf("got rule %s at %s, want node-modules at the outer node_modules", got.RuleID, got.MatchedPath)
	}
}

// TestExplainInheritsAncestorProtection: a path inside a matched directory
// that merely *contains* a protected location is reported as PROTECTED,
// because cleaning the match would delete the protected location too.
func TestExplainInheritsAncestorProtection(t *testing.T) {
	e := newEnv(t, &rules.UserConfig{Rules: []*rules.Rule{{
		ID: "too-broad", Category: "C", Tier: safety.TierSafe, Description: "d", Source: "u", User: true,
		Match: rules.Match{Path: rules.StringList{"~/Library/Application Support"}},
	}}})
	h := e.s.Home
	testutil.Build(t, h, testutil.Tree{
		"Library/Application Support/AddressBook/db": testutil.File{Size: 1},
		"Library/Application Support/SomeApp/x":      testutil.File{Size: 1},
	})
	got := e.cls.Explain(filepath.Join(h, "Library/Application Support/SomeApp/x"), nil)
	if got.RuleID != "too-broad" || got.Tier != safety.TierProtected || !strings.Contains(got.Override, "AddressBook") {
		t.Errorf("got %+v, want PROTECTED via the matched ancestor containing AddressBook", got)
	}
}

func TestHomebrewOldVersions(t *testing.T) {
	e := newEnv(t, nil)
	brew := filepath.Join(e.s.Home, "brew")
	testutil.Build(t, e.s.Home, testutil.Tree{
		"brew/Cellar/node/20.1.0/bin/node": testutil.File{Size: 2_000_000},
		"brew/Cellar/node/22.3.0/bin/node": testutil.File{Size: 2_100_000},
		"brew/Cellar/node/18.0.0/bin/node": testutil.File{Size: 1_900_000},
		"brew/Cellar/jq/1.7/bin/jq":        testutil.File{Size: 100},
		"brew/Cellar/git/2.40/bin/git":     testutil.File{Size: 100}, // two versions, no opt link: left alone
		"brew/Cellar/git/2.45/bin/git":     testutil.File{Size: 100},
		"brew/opt/node":                    testutil.Symlink{Target: "../Cellar/node/22.3.0"},
		"brew/opt/jq":                      testutil.Symlink{Target: "../Cellar/jq/1.7"},
	})
	e.cls.BrewPrefixes = []string{brew}
	_, fs := e.scan(t)
	var old []string
	for _, f := range fs {
		if f.RuleID == "homebrew-old-versions" {
			old = append(old, strings.TrimPrefix(f.Path, brew+"/"))
			if !f.NativeOnly || strings.Join(f.NativeClean, " ") != "brew cleanup" || f.Tier != safety.TierSafe || f.Size < 1_900_000 {
				t.Errorf("finding = %+v", f)
			}
		}
	}
	if strings.Join(sortStrings(old), ",") != "Cellar/node/18.0.0,Cellar/node/20.1.0" {
		t.Errorf("old versions = %v", old)
	}
}

func sortStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// TestExplainInsideDeferredFolder: a project inside an old Downloads folder
// is explained by its own rule, not hidden by the folder's match.
func TestExplainInsideDeferredFolder(t *testing.T) {
	e := newEnv(t, nil)
	h := e.s.Home
	testutil.Build(t, h, testutil.Tree{
		"Downloads/study/proj/package.json":        testutil.File{Size: 1, MTime: days(90)},
		"Downloads/study/proj/node_modules/x/x.js": testutil.File{Size: 1, MTime: days(90)},
	})
	res, fs := e.scan(t)
	got := e.cls.Explain(filepath.Join(h, "Downloads/study/proj/node_modules"), &ScanData{Result: res, Findings: fs})
	if got.RuleID != "node-modules" || got.Tier != safety.TierSafe {
		t.Errorf("got %+v", got)
	}
}
