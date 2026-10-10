package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

func TestRulesPackageIsReadOnly(t *testing.T) {
	testutil.AssertReadOnlyPackage(t, ".")
}

func builtinSet(t *testing.T, home string, now time.Time, extra ...*Rule) *Set {
	t.Helper()
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(Options{Home: home, Rules: append(b, extra...), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuiltinRulesValid(t *testing.T) {
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 40 {
		t.Errorf("only %d built-in rules loaded", len(b))
	}
	if _, err := NewSet(Options{Home: "/Users/x", Rules: b}); err != nil {
		t.Fatalf("built-in rules invalid: %v", err)
	}
}

// TestBuiltinPolicy guards against sloppy future rules: a name-based rule
// that may delete things (SAFE/CAUTION) needs a marker proving what the
// folder is, and must either be a project artifact (only in your own
// folders) or be confined with under: to the area where that tool lives
// (e.g. Chromium caches under ~/Library, next to Chromium's profile files).
func TestBuiltinPolicy(t *testing.T) {
	b, _ := Builtin()
	unambiguous := map[string]bool{"python-caches": true} // __pycache__ etc. are never user data
	for _, r := range b {
		if !r.Tier.Deletable() {
			continue
		}
		m := r.Match
		if len(m.DirName) == 0 && len(m.Name) == 0 && len(m.Ext) == 0 {
			continue
		}
		if !m.Project && m.Under == "" {
			t.Errorf("%s: deletable name-based rule must set project: true or under:", r.ID)
		}
		hasMarker := len(m.RequireSiblingAny)+len(m.RequireChildAny)+len(m.RequireParentMarker) > 0
		if !hasMarker && !unambiguous[r.ID] {
			t.Errorf("%s: deletable name-based rule needs a marker", r.ID)
		}
	}
}

func TestValidation(t *testing.T) {
	ok := func() *Rule {
		return &Rule{ID: "x", Category: "C", Tier: safety.TierSafe, Description: "d", Source: "test",
			Match: Match{Path: StringList{"~/a/b"}}}
	}
	tests := []struct {
		name   string
		mutate func(*Rule)
		want   string
	}{
		{"bad id", func(r *Rule) { r.ID = "Bad ID" }, "id must be"},
		{"no category", func(r *Rule) { r.Category = "" }, "category"},
		{"no tier", func(r *Rule) { r.Tier = safety.TierUnknown }, "tier is required"},
		{"no description", func(r *Rule) { r.Description = "" }, "description"},
		{"no selector", func(r *Rule) { r.Match = Match{} }, "needs one of"},
		{"two selectors", func(r *Rule) { r.Match.DirName = StringList{"x"} }, "exactly one selector"},
		{"relative path", func(r *Rule) { r.Match.Path = StringList{"a/b"} }, "absolute"},
		{"unclean path", func(r *Rule) { r.Match.Path = StringList{"~/a/../b"} }, "not clean"},
		{"bad glob", func(r *Rule) { r.Match = Match{Glob: StringList{"~/a/[b"}} }, "glob"},
		{"partial **", func(r *Rule) { r.Match = Match{Glob: StringList{"~/a**/b"}} }, "whole path component"},
		{"name with slash", func(r *Rule) { r.Match = Match{Name: StringList{"a/b"}} }, "single path component"},
		{"bad ext", func(r *Rule) { r.Match = Match{Ext: StringList{"dmg"}} }, "look like"},
		{"bad type", func(r *Rule) { r.Match.Type = "symlink" }, "type must be"},
		{"dir_name file", func(r *Rule) { r.Match = Match{DirName: StringList{"x"}, Type: "file"} }, "dir_name cannot"},
		{"bad marker", func(r *Rule) { r.Match.RequireSiblingAny = []string{"../x"} }, "marker"},
		{"stale without project", func(r *Rule) { r.StaleAfterDays = 3 }, "requires project"},
		{"native_only alone", func(r *Rule) { r.NativeOnly = true }, "requires native_clean"},
		{"unknown command", func(r *Rule) { r.NativeClean = []string{"rm", "-rf", "/"} }, "not in the allowed list"},
		{"user native", func(r *Rule) { r.User = true; r.NativeClean = []string{"go", "clean"} }, "user rules cannot run commands"},
		{"negative age", func(r *Rule) { r.Match.MinAgeDays = -1 }, "negative"},
	}
	if err := ok().validate(); err != nil {
		t.Fatalf("baseline rule invalid: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ok()
			tt.mutate(r)
			err := r.validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestDuplicateIDsAndBadExcludes(t *testing.T) {
	r := func() *Rule {
		return &Rule{ID: "dup", Category: "C", Tier: safety.TierSafe, Description: "d", Source: "s", Match: Match{Path: StringList{"/a/b"}}}
	}
	_, err := NewSet(Options{Home: "/Users/x", Rules: []*Rule{r(), r()}, Excludes: []string{"relative/x"}})
	if err == nil || !strings.Contains(err.Error(), "already defined") || !strings.Contains(err.Error(), "exclude") {
		t.Errorf("err = %v, want duplicate id and exclude errors together", err)
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]Size{"0": 0, "500MB": 500e6, "2GB": 2e9, "1.5 GB": 1.5e9, "10KiB": 10240, "3gib": 3 << 30, "7b": 7}
	for in, want := range good {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "MB", "-1MB", "5 parsecs", "1e9"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) succeeded", in)
		}
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		pat, path string
		want      bool
	}{
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/x/c", false},
		{"/a/**/c", "/a/c", true},
		{"/a/**/c", "/a/b/x/c", true},
		{"/a/**", "/a", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**/c", "/a/b/c/d", false},
		{"/A/B*", "/a/bee", true}, // case-insensitive
		{"/a/b", "/a/b/c", false},
	}
	for _, tt := range tests {
		if got := compileGlob(tt.pat).match(splitLower(tt.path)); got != tt.want {
			t.Errorf("glob %q on %q = %v, want %v", tt.pat, tt.path, got, tt.want)
		}
	}
}

func TestMatchBuiltin(t *testing.T) {
	s := testutil.NewSandbox(t)
	h := s.Home
	now := time.Now()
	old := now.Add(-90 * 24 * time.Hour)
	testutil.Build(t, h, testutil.Tree{
		"code/web/package.json":                                      testutil.File{Size: 1},
		"code/web/node_modules/x":                                    testutil.File{Size: 1},
		"code/web/dist/a.js":                                         testutil.File{Size: 1},
		"code/plain/build/x":                                         testutil.File{Size: 1}, // no package.json
		"code/plain/node_modules/x":                                  testutil.File{Size: 1}, // no package.json
		"code/rs/Cargo.toml":                                         testutil.File{Size: 1},
		"code/rs/target/x":                                           testutil.File{Size: 1},
		"code/notrust/target/x":                                      testutil.File{Size: 1},
		"code/py/.venv/pyvenv.cfg":                                   testutil.File{Size: 1},
		"code/py/venv/x":                                             testutil.File{Size: 1}, // no pyvenv.cfg
		"code/py/pkg/__pycache__/a.pyc":                              testutil.File{Size: 1},
		"code/ios/Podfile":                                           testutil.File{Size: 1},
		"code/ios/Pods/x":                                            testutil.File{Size: 1},
		"code/ng/angular.json":                                       testutil.File{Size: 1},
		"code/ng/.angular/cache/x":                                   testutil.File{Size: 1},
		"code/jvm/build.gradle":                                      testutil.File{Size: 1},
		"code/jvm/.gradle/x":                                         testutil.File{Size: 1},
		".vscode/extensions/ext/package.json":                        testutil.File{Size: 1},
		".vscode/extensions/ext/node_modules/x":                      testutil.File{Size: 1},
		"Library/Application Support/Tool/package.json":              testutil.File{Size: 1},
		"Library/Application Support/Tool/node_modules/x":            testutil.File{Size: 1},
		"Applications/Foo.app/Contents/Resources/app/package.json":   testutil.File{Size: 1},
		"Applications/Foo.app/Contents/Resources/app/node_modules/x": testutil.File{Size: 1},
	})

	type tc struct {
		path  string
		isDir bool
		size  uint64
		mtime time.Time
		want  string // rule id, "" = no match
	}
	p := func(rel string) string { return filepath.Join(h, rel) }
	tests := []tc{
		{p("code/web/node_modules"), true, 0, now, "node-modules"},
		{p("code/web/dist"), true, 0, now, "js-build-output"},
		{p("code/plain/build"), true, 0, now, ""},          // build/ without a project marker
		{p("code/plain/node_modules"), true, 0, now, ""},   // node_modules without package.json
		{p("code/rs/target"), true, 0, now, "rust-target"}, //
		{p("code/notrust/target"), true, 0, now, ""},       // target without Cargo.toml
		{p("code/py/.venv"), true, 0, now, "python-venv"},
		{p("code/py/venv"), true, 0, now, ""}, // no pyvenv.cfg inside
		{p("code/py/pkg/__pycache__"), true, 0, now, "python-caches"},
		{p("code/ios/Pods"), true, 0, now, "cocoapods-pods"},
		{p("code/ng/.angular"), true, 0, now, "angular-cache"},
		{p("code/jvm/.gradle"), true, 0, now, "gradle-project"},
		{p("code/web/node_modules"), false, 0, now, ""}, // a file named node_modules
		// Installed tools and app bundles are not workspaces.
		{p(".vscode/extensions/ext/node_modules"), true, 0, now, ""},
		{p("Library/Application Support/Tool/node_modules"), true, 0, now, ""},
		{p("Applications/Foo.app/Contents/Resources/app/node_modules"), true, 0, now, ""},
		// Exact paths beat globs; Apple caches are stricter than other caches.
		{p("Library/Caches/go-build"), true, 0, now, "go-build-cache"},
		{p("Library/Caches/Homebrew"), true, 0, now, "homebrew-cache"},
		{p("Library/Caches/com.example.App"), true, 0, now, "user-app-caches"},
		{p("Library/Caches/com.apple.Safari"), true, 0, now, "apple-app-caches"},
		{p("library/caches/GO-BUILD"), true, 0, now, "go-build-cache"}, // case-insensitive
		{p("Library/Caches"), true, 0, now, ""},
		{p("Library/Logs/DiagnosticReports"), true, 0, now, "diagnostic-reports"},
		{p("Library/Logs/Some.log"), false, 10, now, "user-logs"},
		{"/private/var/log/system.log", false, 10, now, "system-logs"},
		{"/private/var/folders", true, 0, now, "var-folders"},
		{p("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"), false, 1, now, "docker-desktop-disk"},
		{p("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"), true, 0, now, ""}, // files only
		{p(".Trash"), true, 0, now, "trash"},
		{p("Pictures/Photos Library.photoslibrary"), true, 0, now, "photos-library"},
		{p("VMs/Win11.pvm"), true, 0, now, "vm-bundles"},
		// Size and age conditions on files.
		{p("Movies/trip.mov"), false, 600e6, now, "large-media"},
		{p("Movies/clip.mov"), false, 100e6, now, ""},
		{"/tmp/trip.mov", false, 600e6, now, ""}, // not under home
		{p("Desktop/Setup.dmg"), false, 10e6, old, "installers"},
		{p("Desktop/Setup.dmg"), false, 10e6, now, ""}, // too recent
		// Old downloads beat the extension rules; recent ones fall through.
		{p("Downloads/Setup.dmg"), false, 10e6, old, "old-downloads"},
		{p("Downloads/new.mov"), false, 600e6, now, "large-media"},
	}
	set := builtinSet(t, h, now)
	for _, tt := range tests {
		res, ok := set.Match(Candidate{Path: tt.path, IsDir: tt.isDir, Size: tt.size, MTime: tt.mtime})
		got := ""
		if ok {
			got = res.Rule.ID
			if res.Reason == "" {
				t.Errorf("%s: empty reason", tt.path)
			}
		}
		if got != tt.want {
			t.Errorf("Match(%s, dir=%v) = %q (%s), want %q", strings.TrimPrefix(tt.path, h), tt.isDir, got, res.Reason, tt.want)
		}
	}

	// Directories defer size/age checks to the caller.
	res, ok := set.Match(Candidate{Path: p("Downloads/OldFolder"), IsDir: true})
	if !ok || res.Rule.ID != "old-downloads" || !res.Deferred {
		t.Errorf("Downloads dir: %+v ok=%v, want deferred old-downloads", res, ok)
	}
	// Project roots are reported.
	res, _ = set.Match(Candidate{Path: p("code/py/pkg/__pycache__"), IsDir: true})
	if res.ProjectRoot != p("code/py/pkg") && res.ProjectRoot != p("code/py") {
		t.Errorf("ProjectRoot = %q", res.ProjectRoot)
	}
	res, _ = set.Match(Candidate{Path: p("code/web/node_modules"), IsDir: true})
	if res.ProjectRoot != p("code/web") || !strings.Contains(res.Reason, "package.json next to it") {
		t.Errorf("node_modules result = %+v", res)
	}
}

func TestPriorityTieGoesToStricterTier(t *testing.T) {
	s := testutil.NewSandbox(t)
	mk := func(id string, tier safety.Tier) *Rule {
		return &Rule{ID: id, Category: "C", Tier: tier, Description: "d", Source: "t", Match: Match{Glob: StringList{"~/x/*"}}}
	}
	set, err := NewSet(Options{Home: s.Home, Rules: []*Rule{mk("lenient", safety.TierSafe), mk("strict", safety.TierReview)}})
	if err != nil {
		t.Fatal(err)
	}
	res, ok := set.Match(Candidate{Path: filepath.Join(s.Home, "x", "y"), IsDir: true})
	if !ok || res.Rule.ID != "strict" {
		t.Errorf("got %v, want the stricter rule", res.Rule)
	}
}

func TestExcluded(t *testing.T) {
	set, err := NewSet(Options{Home: "/Users/u", Excludes: []string{"~/code/keep", "~/code/**/vendored"}})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"/Users/u/code/keep":                   true,
		"/Users/u/code/keep/node_modules":      true,
		"/Users/u/code/keeper/node_modules":    false,
		"/Users/u/code/a/b/vendored/x":         true,
		"/Users/u/code/a/node_modules":         false,
		"/Users/u/CODE/Keep/node_modules/deep": true,
	} {
		if got := set.Excluded(p); got != want {
			t.Errorf("Excluded(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestUserConfig(t *testing.T) {
	s := testutil.NewSandbox(t)
	write := func(name, body string) string {
		p := filepath.Join(s.Dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", `
rules:
  - id: my-cache
    category: "Mine"
    match:
      path: ~/scratch/cache
    tier: SAFE
    description: "my cache"
exclude:
  - ~/code/keep/**
`)
	cfg, err := LoadUserConfig(good, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || !cfg.Rules[0].User || cfg.Rules[0].Source != good || len(cfg.Exclude) != 1 {
		t.Errorf("cfg = %+v", cfg)
	}
	set := builtinSet(t, s.Home, time.Now(), cfg.Rules...)
	if res, ok := set.Match(Candidate{Path: filepath.Join(s.Home, "scratch/cache"), IsDir: true}); !ok || res.Rule.ID != "my-cache" {
		t.Error("user rule did not match")
	}

	typo := write("typo.yaml", "rules:\n  - id: x\n    categroy: C\n")
	if _, err := LoadUserConfig(typo, true); err == nil || !strings.Contains(err.Error(), "categroy") {
		t.Errorf("typo: err = %v, want unknown field error", err)
	}

	native := write("native.yaml", `
rules:
  - id: evil
    category: C
    match: {path: ~/x/y}
    tier: SAFE
    description: d
    native_clean: [go, clean]
`)
	cfg, err = LoadUserConfig(native, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSet(Options{Home: s.Home, Rules: cfg.Rules}); err == nil || !strings.Contains(err.Error(), "cannot run commands") {
		t.Errorf("native user rule: err = %v", err)
	}

	collide := write("collide.yaml", "rules:\n  - {id: node-modules, category: C, match: {path: ~/x/y}, tier: SAFE, description: d}\n")
	cfg, _ = LoadUserConfig(collide, true)
	b, _ := Builtin()
	if _, err := NewSet(Options{Home: s.Home, Rules: append(b, cfg.Rules...)}); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("id collision: err = %v", err)
	}

	missing := filepath.Join(s.Dir, "missing.yaml")
	if cfg, err := LoadUserConfig(missing, false); err != nil || len(cfg.Rules) != 0 {
		t.Errorf("optional missing config: %v", err)
	}
	if _, err := LoadUserConfig(missing, true); err == nil {
		t.Error("required missing config: want error")
	}
	empty := write("empty.yaml", "")
	if _, err := LoadUserConfig(empty, true); err != nil {
		t.Errorf("empty config: %v", err)
	}
	badTier := write("badtier.yaml", "rules:\n  - {id: x, category: C, match: {path: ~/x/y}, tier: SORTA, description: d}\n")
	if _, err := LoadUserConfig(badTier, true); err == nil || !strings.Contains(err.Error(), "SORTA") {
		t.Errorf("bad tier: err = %v", err)
	}
}

func TestIsCleanAgreesWithClean(t *testing.T) {
	for _, p := range []string{"/", "/a", "/a/b", "/a/", "//a", "/a//b", "/a/./b", "/a/../b", "/a/.", "/a/..", "/.a/..b/c.", "/a/b.c", ""} {
		if got, want := isClean(p), p != "" && filepath.Clean(p) == p; got != want {
			t.Errorf("isClean(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestNamePattern(t *testing.T) {
	for _, tt := range []struct {
		pat, name string
		want      bool
	}{
		{"*.pvm", "win.pvm", true}, {"*.pvm", "win.pvmx", false}, {"node_mod*", "node_modules", true},
		{"node_mod*", "xnode_modules", false}, {"a?c", "abc", true}, {"[ab]x", "bx", true}, {"*", "anything", true},
	} {
		if got := newNamePattern(tt.pat).match(tt.name); got != tt.want {
			t.Errorf("%q on %q = %v", tt.pat, tt.name, got)
		}
	}
}

func TestGlobQuickNeverRejectsAMatch(t *testing.T) {
	globs := []string{"/a/b/*", "/a/**/c", "/a/*/c/d", "/**/x", "/A/B*", "/a/b"}
	paths := []string{"/a/b/c", "/a/b", "/a/c", "/a/x/y/c", "/a/x/c/d", "/q/x", "/x", "/a/bee", "/A/B/c", "/ab/c"}
	for _, g := range globs {
		pg := compileGlob(g)
		for _, p := range paths {
			if pg.match(splitLower(p)) && !pg.quick(p) {
				t.Errorf("quick rejected matching path %s for glob %s", p, g)
			}
		}
	}
}

func BenchmarkMatchNoHit(b *testing.B) {
	bset, _ := Builtin()
	set, err := NewSet(Options{Home: "/Users/me", Rules: bset})
	if err != nil {
		b.Fatal(err)
	}
	c := Candidate{Path: "/Users/me/Documents/projects/thesis/chapters/chapter-03/figure-12.png", Size: 1000}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		set.Match(c)
	}
}

func TestUserFilesRulesSkipAppInternals(t *testing.T) {
	set := builtinSet(t, "/Users/u", time.Now())
	for p, want := range map[string]string{
		"/Users/u/Movies/trip.mov":                               "large-media",
		"/Users/u/Library/Application Support/App/vm/rootfs.img": "",
		"/Users/u/Library/Containers/x/Data/tmp/Installer.dmg":   "",
		"/Users/u/.cache/models/blob.zip":                        "",
	} {
		res, ok := set.Match(Candidate{Path: p, Size: 600e6, MTime: time.Now().Add(-100 * 24 * time.Hour)})
		got := ""
		if ok {
			got = res.Rule.ID
		}
		if got != want {
			t.Errorf("%s matched %q, want %q", p, got, want)
		}
	}
}

// TestSyntheticRulesHaveDetectors: a synthetic rule matches nothing by
// itself, and the cleaner's content-check policy depends on its detector, so
// every one must be registered (and every registration must be used).
func TestSyntheticRulesHaveDetectors(t *testing.T) {
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	synthetic := map[string]bool{}
	for _, r := range b {
		if !r.Synthetic {
			continue
		}
		synthetic[r.ID] = true
		if _, ok := DetectorFor(r.ID); !ok {
			t.Errorf("synthetic rule %s has no detector in detectors.go", r.ID)
		}
	}
	for id := range detectors {
		if !synthetic[id] {
			t.Errorf("detector %s has no synthetic rule", id)
		}
	}
	for _, vs := range versionStores {
		if !synthetic[vs.ruleID] {
			t.Errorf("version store %s has no synthetic rule", vs.ruleID)
		}
	}
}
