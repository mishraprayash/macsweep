package cleaner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/audit"
	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

type env struct {
	s     *testutil.Sandbox
	set   *rules.Set
	guard *safety.Guard
	trash string
}

func newEnv(t *testing.T, tree testutil.Tree, userRules ...*rules.Rule) *env {
	t.Helper()
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, tree)
	b, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.NewSet(rules.Options{Home: s.Home, Rules: append(b, userRules...), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	g, err := safety.NewGuard(s.Home)
	if err != nil {
		t.Fatal(err)
	}
	trash := filepath.Join(s.Home, ".Trash")
	if err := os.MkdirAll(trash, 0o700); err != nil {
		t.Fatal(err)
	}
	return &env{s: s, set: set, guard: g, trash: trash}
}

func (e *env) scan(t *testing.T) *cache.Scan {
	t.Helper()
	cls := classifier.New(e.set, e.guard, func() time.Time { return now })
	res, err := scanner.Scan(context.Background(), scanner.Options{Root: e.s.Home, Visit: cls.Visit})
	if err != nil {
		t.Fatal(err)
	}
	fs := cls.Findings(res)
	res.Tree.Compact(1_000_000)
	return &cache.Scan{Result: res, Findings: fs}
}

func (e *env) plan(t *testing.T, sc *cache.Scan, sel Selector, o Options) *Plan {
	t.Helper()
	if o.Now.IsZero() {
		o.Now = now
	}
	p, err := BuildPlan(sc, sel, e.set, e.guard, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type fakeRunner struct {
	calls [][]string
	err   error
}

func (f *fakeRunner) Run(_ context.Context, cmd []string, _ io.Writer) error {
	f.calls = append(f.calls, cmd)
	return f.err
}

func (e *env) executor(t *testing.T, r Runner) (*Executor, string) {
	t.Helper()
	path := audit.DefaultPath(e.s.Home)
	l, err := audit.Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if r == nil {
		r = &fakeRunner{}
	}
	return &Executor{Guard: e.guard, Rules: e.set, TrashDir: e.trash, Audit: l, Runner: r, Out: io.Discard}, path
}

func rel(e *env, p string) string { return strings.TrimPrefix(p, e.s.Home+"/") }

func itemPaths(e *env, p *Plan) map[string]Item {
	m := map[string]Item{}
	for _, it := range p.Items {
		m[rel(e, it.Path)] = it
	}
	return m
}

func noLookPath(string) (string, error)    { return "", errors.New("not installed") }
func yesLookPath(c string) (string, error) { return "/usr/bin/" + c, nil }

func devTree() testutil.Tree {
	return testutil.Tree{
		"code/web/package.json":                                           testutil.File{Size: 10, MTime: days(3)},
		"code/web/node_modules/r/i.js":                                    testutil.File{Size: 2_000_000},
		"code/web/.next/cache/x":                                          testutil.File{Size: 1_500_000},
		"code/web/dist/bundle.js":                                         testutil.File{Size: 300_000},
		"code/old/package.json":                                           testutil.File{Size: 10, MTime: days(200)},
		"code/old/node_modules/r/i.js":                                    testutil.File{Size: 1_200_000},
		"code/rs/Cargo.toml":                                              testutil.File{Size: 10, MTime: days(1)},
		"code/rs/target/debug/app":                                        testutil.File{Size: 1_100_000},
		"code/py/.venv/pyvenv.cfg":                                        testutil.File{Size: 10},
		"code/py/.venv/lib/torch.so":                                      testutil.File{Size: 1_300_000},
		"Library/Caches/com.example/blob":                                 testutil.File{Size: 1_000_000},
		"Library/Caches/go-build/aa":                                      testutil.File{Size: 1_000_000},
		"Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw": testutil.File{Size: 1_000_000},
		"Library/Logs/DiagnosticReports/a.ips":                            testutil.File{Size: 5_000},
		"Library/Logs/DiagnosticReports/b.ips":                            testutil.File{Size: 5_000},
		"Library/Mobile Documents/doc.pages":                              testutil.File{Size: 1_000},
		"Downloads/old.zip":                                               testutil.File{Size: 1_000, MTime: days(90)},
		".Trash/deleted.txt":                                              testutil.File{Size: 1_000},
	}
}

func TestPlanDefaultsToSafeOnly(t *testing.T) {
	e := newEnv(t, devTree())
	p := e.plan(t, e.scan(t), Selector{}, Options{LookPath: yesLookPath})
	got := itemPaths(e, p)

	for _, want := range []string{"code/web/node_modules", "code/web/.next", "code/web/dist", "code/old/node_modules",
		"code/rs/target", "Library/Caches/com.example", "Library/Caches/go-build", "Library/Logs/DiagnosticReports"} {
		if _, ok := got[want]; !ok {
			t.Errorf("plan missing %s", want)
		}
	}
	for p, it := range got {
		if it.Tier != safety.TierSafe {
			t.Errorf("%s: tier %v in a default plan", p, it.Tier)
		}
	}
	if got["Library/Caches/go-build"].Method != MethodNative || strings.Join(got["Library/Caches/go-build"].Command, " ") != "go clean -cache" {
		t.Errorf("go-build should use go clean: %+v", got["Library/Caches/go-build"])
	}
	if !got["Library/Logs/DiagnosticReports"].Contents {
		t.Error("DiagnosticReports should be emptied, not removed")
	}
	if got["code/web/node_modules"].Method != MethodTrash {
		t.Error("default method should be trash")
	}

	left := map[string]string{}
	for _, l := range p.Left {
		left[rel(e, l.Path)] = l.Reason
	}
	if !strings.Contains(left["code/py/.venv"], "--tier caution") {
		t.Errorf(".venv left reason = %q", left["code/py/.venv"])
	}
	if !strings.Contains(left[".Trash"], "--permanent") {
		t.Errorf("Trash left reason = %q", left[".Trash"])
	}
	if p.NeverCleaned < 2 { // iCloud Drive (PROTECTED), old download (REVIEW)
		t.Errorf("NeverCleaned = %d", p.NeverCleaned)
	}
}

func TestPlanFilters(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	tests := []struct {
		name string
		sel  Selector
		want []string
	}{
		{"names node_modules and .next", Selector{Names: []string{"node_modules", ".next"}},
			[]string{"code/old/node_modules", "code/web/.next", "code/web/node_modules"}},
		{"name glob", Selector{Names: []string{"node_mod*"}}, []string{"code/old/node_modules", "code/web/node_modules"}},
		{"rule", Selector{Rules: []string{"rust-target"}}, []string{"code/rs/target"}},
		{"category", Selector{Categories: []string{"dev: javascript"}},
			[]string{"code/old/node_modules", "code/web/.next", "code/web/dist", "code/web/node_modules"}},
		{"under", Selector{Under: []string{"~/code/web"}}, []string{"code/web/.next", "code/web/dist", "code/web/node_modules"}},
		{"under is not a prefix match", Selector{Under: []string{"~/code/we"}}, nil},
		{"older-than uses project activity", Selector{Names: []string{"node_modules"}, OlderThan: 30 * 24 * time.Hour},
			[]string{"code/old/node_modules"}},
		{"stale", Selector{StaleOnly: true}, []string{"code/old/node_modules"}},
		{"min-size", Selector{Names: []string{"*"}, MinSize: 1_400_000}, []string{"code/web/.next", "code/web/node_modules"}},
		{"exclude", Selector{Names: []string{"node_modules"}, Excludes: []string{"~/code/old/**"}}, []string{"code/web/node_modules"}},
		{"caution adds venv", Selector{MaxTier: safety.TierCaution, Names: []string{".venv"}}, []string{"code/py/.venv"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := e.plan(t, sc, tt.sel, Options{LookPath: yesLookPath})
			var got []string
			for _, it := range p.Items {
				got = append(got, rel(e, it.Path))
			}
			if strings.Join(sorted(got), ",") != strings.Join(sorted(tt.want), ",") {
				t.Errorf("got %v, want %v", sorted(got), sorted(tt.want))
			}
		})
	}
	if _, err := BuildPlan(sc, Selector{MaxTier: safety.TierReview}, e.set, e.guard, Options{}); err == nil {
		t.Error("--tier review accepted")
	}
	if _, err := BuildPlan(sc, Selector{Names: []string{"a/b"}}, e.set, e.guard, Options{}); err == nil {
		t.Error("--name with a slash accepted")
	}
}

func sorted(s []string) []string {
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

func TestPlanNativeCommands(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)

	p := e.plan(t, sc, Selector{MaxTier: safety.TierCaution}, Options{LookPath: yesLookPath})
	groups := map[string]int{}
	for _, g := range p.NativeGroups() {
		groups[strings.Join(g.Command, " ")] = len(g.Items)
	}
	if groups["go clean -cache"] != 1 || groups["docker system prune --force"] != 1 {
		t.Errorf("native groups = %v", groups)
	}

	// Tools missing: go-build falls back to the Trash, Docker (native only) is left out.
	p = e.plan(t, sc, Selector{MaxTier: safety.TierCaution}, Options{LookPath: noLookPath})
	got := itemPaths(e, p)
	if got["Library/Caches/go-build"].Method != MethodTrash {
		t.Errorf("go-build without go: %+v", got["Library/Caches/go-build"])
	}
	for _, it := range p.Items {
		if strings.HasSuffix(it.Path, "Docker.raw") {
			t.Error("Docker.raw planned for deletion without docker")
		}
	}

	// --skip-native: never run commands; native-only items are left out.
	p = e.plan(t, sc, Selector{MaxTier: safety.TierCaution}, Options{LookPath: yesLookPath, SkipNative: true})
	if len(p.NativeGroups()) != 0 {
		t.Error("--skip-native still planned commands")
	}
	for _, it := range p.Items {
		if strings.HasSuffix(it.Path, "Docker.raw") {
			t.Error("Docker.raw planned for file deletion")
		}
	}
}

// TestPlanNeverIncludesProtectedOrReview forges a saved scan that claims
// protected and review paths are SAFE (as a tampered or stale cache file
// might). The plan must still exclude all of them.
func TestPlanNeverIncludesProtectedOrReview(t *testing.T) {
	e := newEnv(t, testutil.Tree{"x": testutil.File{Size: 1}})
	h := e.s.Home
	forged := []string{
		h, h + "/.ssh", h + "/.ssh/id_ed25519", h + "/Library/Keychains", h + "/Library", h + "/.aws/credentials",
		h + "/Library/Mobile Documents", h + "/Pictures/Photos Library.photoslibrary", h + "/code/app/.git",
		h + "/code/app/.env.local", h + "/Library/Logs/sweep", h + "/Documents", "/System/Library",
		"/usr/bin", "/Applications/Safari.app", "/private/etc", "/private/var/vm/sleepimage", "/",
		h + "/code/../.ssh/x", "relative/path",
	}
	sc := &cache.Scan{Result: &scanner.Result{Root: "/", Tree: &scanner.Node{Name: "/"}}}
	for _, p := range forged {
		for _, tier := range []safety.Tier{safety.TierSafe, safety.TierCaution, safety.TierReview, safety.TierProtected} {
			sc.Findings = append(sc.Findings, classifier.Finding{Path: p, RuleID: "user-app-caches", Tier: tier, Size: 1, IsDir: true})
		}
	}
	for _, permanent := range []bool{false, true} {
		p := e.plan(t, sc, Selector{MaxTier: safety.TierCaution}, Options{Permanent: permanent, LookPath: yesLookPath})
		if len(p.Items) != 0 {
			for _, it := range p.Items {
				t.Errorf("forged %s (%v) entered the plan", it.Path, it.Tier)
			}
		}
	}
}

func TestExecuteTrash(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	// Something already in the Trash with the same name must not be overwritten.
	testutil.Build(t, e.trash, testutil.Tree{"node_modules/keep-me": testutil.File{Size: 1}})

	p := e.plan(t, sc, Selector{Names: []string{"node_modules", ".next"}}, Options{LookPath: yesLookPath})
	ex, logPath := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)

	if sum.Trashed != 3 || sum.Failed != 0 || sum.Skipped != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	for _, gone := range []string{"code/web/node_modules", "code/web/.next", "code/old/node_modules"} {
		if _, err := os.Lstat(filepath.Join(e.s.Home, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists", gone)
		}
	}
	for _, kept := range []string{"code/web/package.json", "code/web/dist/bundle.js", "code/rs/target/debug/app", "Library/Caches/com.example/blob"} {
		if _, err := os.Lstat(filepath.Join(e.s.Home, kept)); err != nil {
			t.Errorf("%s was touched: %v", kept, err)
		}
	}
	for _, inTrash := range []string{"node_modules/keep-me", "node_modules 2", "node_modules 3", ".next"} {
		if _, err := os.Lstat(filepath.Join(e.trash, inTrash)); err != nil {
			t.Errorf("Trash missing %s: %v", inTrash, err)
		}
	}

	recs := readAudit(t, logPath)
	if len(recs) != 3 {
		t.Fatalf("audit has %d records, want 3", len(recs))
	}
	for _, r := range recs {
		if r.Action != "trash" || r.Result != audit.ResultOK || r.TrashPath == "" || r.RuleID == "" || r.Tier != "SAFE" || r.Size == 0 {
			t.Errorf("audit record = %+v", r)
		}
	}
}

func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestExecutePermanentAndContents(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{Rules: []string{"diagnostic-reports", "trash", "rust-target"}}, Options{Permanent: true, LookPath: yesLookPath})
	if len(p.Items) != 3 {
		t.Fatalf("plan = %+v", p.Items)
	}
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)
	if sum.Deleted != 4 || sum.Failed+sum.Skipped != 0 { // 2 reports + 1 trash item + target
		t.Fatalf("summary = %+v", sum)
	}
	for _, kept := range []string{"Library/Logs/DiagnosticReports", ".Trash", "code/rs/Cargo.toml"} {
		if _, err := os.Lstat(filepath.Join(e.s.Home, kept)); err != nil {
			t.Errorf("container/marker %s removed: %v", kept, err)
		}
	}
	for _, gone := range []string{"Library/Logs/DiagnosticReports/a.ips", ".Trash/deleted.txt", "code/rs/target"} {
		if _, err := os.Lstat(filepath.Join(e.s.Home, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not deleted", gone)
		}
	}
}

func TestExecuteRevalidation(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	h := e.s.Home
	p := e.plan(t, sc, Selector{Names: []string{"node_modules", ".next", "target", "dist"}}, Options{LookPath: yesLookPath})

	// After the scan, before cleaning:
	// 1. web/node_modules was replaced by a different directory (inode change).
	if err := os.RemoveAll(filepath.Join(h, "code/web/node_modules")); err != nil {
		t.Fatal(err)
	}
	testutil.Build(t, h, testutil.Tree{"code/web/node_modules/new": testutil.File{Size: 1}})
	// 2. old/ lost its package.json, so node_modules no longer matches its rule.
	if err := os.Remove(filepath.Join(h, "code/old/package.json")); err != nil {
		t.Fatal(err)
	}
	// 3. rs/target was deleted.
	if err := os.RemoveAll(filepath.Join(h, "code/rs/target")); err != nil {
		t.Fatal(err)
	}
	// 4. .next was swapped for a symlink to the user's documents.
	testutil.Build(t, h, testutil.Tree{"Documents/precious.txt": testutil.File{Size: 1}})
	if err := os.RemoveAll(filepath.Join(h, "code/web/.next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h, "Documents"), filepath.Join(h, "code/web/.next")); err != nil {
		t.Fatal(err)
	}

	ex, logPath := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)
	if sum.Trashed != 1 || sum.Skipped != 4 { // only dist is still valid
		t.Fatalf("summary = %+v", sum)
	}
	for _, kept := range []string{"code/web/node_modules/new", "code/old/node_modules/r/i.js", "Documents/precious.txt"} {
		if _, err := os.Lstat(filepath.Join(h, kept)); err != nil {
			t.Errorf("%s touched: %v", kept, err)
		}
	}
	skipped := 0
	for _, r := range readAudit(t, logPath) {
		if r.Result == audit.ResultSkipped {
			skipped++
			if r.Reason == "" {
				t.Errorf("skip without reason: %+v", r)
			}
		}
	}
	if skipped != 4 {
		t.Errorf("audit logged %d skips, want 4", skipped)
	}
}

// TestExecuteParentSwappedIntoProtected: a project directory replaced by a
// symlink into ~/.ssh after the scan must not lead to anything in ~/.ssh
// being moved.
func TestExecuteParentSwappedIntoProtected(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	h := e.s.Home
	p := e.plan(t, sc, Selector{Names: []string{"node_modules"}, Under: []string{"~/code/web"}}, Options{LookPath: yesLookPath})
	testutil.Build(t, h, testutil.Tree{
		".ssh/package.json":     testutil.File{Size: 1},
		".ssh/node_modules/key": testutil.File{Size: 1},
	})
	if err := os.Rename(filepath.Join(h, "code/web"), filepath.Join(h, "code/web-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h, ".ssh"), filepath.Join(h, "code/web")); err != nil {
		t.Fatal(err)
	}
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)
	if sum.Trashed != 0 || sum.Skipped != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if _, err := os.Lstat(filepath.Join(h, ".ssh/node_modules/key")); err != nil {
		t.Errorf("protected file moved: %v", err)
	}
}

func TestExecuteRefusesDirsWithGitOrEnv(t *testing.T) {
	user := &rules.Rule{ID: "my-builds", Category: "Mine", Tier: safety.TierSafe, Description: "d", Source: "u", User: true,
		Match: rules.Match{Glob: rules.StringList{"~/scratch/*"}}}
	e := newEnv(t, testutil.Tree{
		"scratch/clone/.git/HEAD":             testutil.File{Size: 1},
		"scratch/clone/src.go":                testutil.File{Size: 1},
		"scratch/withenv/sub/.env.local":      testutil.File{Size: 1},
		"scratch/plain/file":                  testutil.File{Size: 1},
		"code/web/package.json":               testutil.File{Size: 1},
		"code/web/dist/.env":                  testutil.File{Size: 1},
		"code/web/node_modules/pkg/.git/HEAD": testutil.File{Size: 1},
		"code/web/node_modules/pkg/i.js":      testutil.File{Size: 1},
	}, user)
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{}, Options{LookPath: yesLookPath})
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)

	h := e.s.Home
	for _, kept := range []string{"scratch/clone/.git/HEAD", "scratch/withenv/sub/.env.local", "code/web/dist/.env"} {
		if _, err := os.Lstat(filepath.Join(h, kept)); err != nil {
			t.Errorf("%s was removed: %v", kept, err)
		}
	}
	for _, gone := range []string{"scratch/plain", "code/web/node_modules"} {
		if _, err := os.Lstat(filepath.Join(h, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not cleaned", gone)
		}
	}
	if sum.Skipped != 3 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestExecuteNative(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{MaxTier: safety.TierCaution, Rules: []string{"go-build-cache", "docker-desktop-disk"}}, Options{LookPath: yesLookPath})
	r := &fakeRunner{}
	ex, logPath := e.executor(t, r)
	sum := ex.Execute(context.Background(), p)
	if len(r.calls) != 2 || sum.NativeRuns != 2 {
		t.Fatalf("calls = %v", r.calls)
	}
	// Native commands never delete files themselves in sweep.
	if _, err := os.Lstat(filepath.Join(e.s.Home, "Library/Caches/go-build/aa")); err != nil {
		t.Error("sweep deleted go-build itself instead of leaving it to go clean")
	}
	for _, rec := range readAudit(t, logPath) {
		if rec.Action != "native" || len(rec.Command) == 0 || rec.Result != audit.ResultOK {
			t.Errorf("audit = %+v", rec)
		}
	}

	r = &fakeRunner{err: errors.New("exit status 1")}
	ex, _ = e.executor(t, r)
	sum = ex.Execute(context.Background(), p)
	if sum.Failed != 2 {
		t.Errorf("failed native: %+v", sum)
	}
}

func TestExecuteCancelled(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{}, Options{LookPath: yesLookPath})
	before := testutil.Snapshot(t, e.s.Home+"/code")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(ctx, p)
	if !sum.Interrupted || len(sum.Outcomes) != 0 {
		t.Errorf("summary = %+v", sum)
	}
	testutil.AssertUnchanged(t, e.s.Home+"/code", before)
}

func TestMoveToTrashNames(t *testing.T) {
	s := testutil.NewSandbox(t)
	trash := filepath.Join(s.Dir, "Trash")
	testutil.Build(t, s.Dir, testutil.Tree{
		"Trash/report.pdf":   testutil.File{Size: 1},
		"Trash/report 2.pdf": testutil.File{Size: 1},
		"Trash/.next":        testutil.Dir{},
		"a/report.pdf":       testutil.File{Content: []byte("new")},
		"a/.next/x":          testutil.File{Size: 1},
	})
	dst, err := moveToTrash(filepath.Join(s.Dir, "a/report.pdf"), trash)
	if err != nil || filepath.Base(dst) != "report 3.pdf" {
		t.Errorf("dst = %s, %v", dst, err)
	}
	if b, _ := os.ReadFile(filepath.Join(trash, "report.pdf")); string(b) == "new" {
		t.Error("existing Trash item overwritten")
	}
	dst, err = moveToTrash(filepath.Join(s.Dir, "a/.next"), trash)
	if err != nil || filepath.Base(dst) != ".next 2" {
		t.Errorf("dotdir dst = %s, %v", dst, err)
	}
}

func TestFindSensitive(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Dir, testutil.Tree{
		"a/deep/x/.git/HEAD":         testutil.File{Size: 1},
		"b/node_modules/p/.git/HEAD": testutil.File{Size: 1},
		"b/node_modules/p/.env":      testutil.File{Size: 1},
		"b/ok.txt":                   testutil.File{Size: 1},
		"c/.envrc":                   testutil.File{Size: 1},
		"d/locked/f":                 testutil.File{Size: 1},
		"d/locked":                   testutil.Dir{Mode: 0o000, Chmod: true},
	})
	for dir, want := range map[string]string{"a": "deep/x/.git", "b": "", "c": ".envrc"} {
		got, err := findSensitive(filepath.Join(s.Dir, dir))
		if err != nil || got != want {
			t.Errorf("findSensitive(%s) = %q, %v; want %q", dir, got, err, want)
		}
	}
	if os.Geteuid() != 0 {
		if _, err := findSensitive(filepath.Join(s.Dir, "d")); err == nil {
			t.Error("unreadable subdirectory should be an error (fail closed)")
		}
	}
}

func TestExecuteCreatesMissingTrash(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	if err := os.RemoveAll(e.trash); err != nil { // the sandbox Trash created by newEnv
		t.Fatal(err)
	}
	p := e.plan(t, sc, Selector{Rules: []string{"rust-target"}}, Options{LookPath: yesLookPath})
	ex, _ := e.executor(t, nil)
	if sum := ex.Execute(context.Background(), p); sum.Trashed != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if fi, err := os.Stat(filepath.Join(e.trash, "target")); err != nil || !fi.IsDir() {
		t.Errorf("target not in recreated Trash: %v", err)
	}
}

// TestEmptyingKeepsProtectedChildren: when a folder is emptied, each child is
// checked by the safety layer on its own.
func TestEmptyingKeepsProtectedChildren(t *testing.T) {
	tree := devTree()
	tree["Library/Logs/DiagnosticReports/.git/HEAD"] = testutil.File{Size: 1}
	tree["Library/Logs/DiagnosticReports/.env.backup"] = testutil.File{Size: 1}
	e := newEnv(t, tree)
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{Rules: []string{"diagnostic-reports"}}, Options{Permanent: true, LookPath: yesLookPath})
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)
	if sum.Deleted != 2 || sum.Skipped != 2 {
		t.Errorf("summary = %+v", sum)
	}
	for _, kept := range []string{".git/HEAD", ".env.backup"} {
		if _, err := os.Lstat(filepath.Join(e.s.Home, "Library/Logs/DiagnosticReports", kept)); err != nil {
			t.Errorf("%s deleted: %v", kept, err)
		}
	}
}

// TestEmptyingRefusesSwappedContainer: a folder scheduled to be emptied that
// is replaced by a symlink to the user's documents must not be emptied.
func TestEmptyingRefusesSwappedContainer(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	h := e.s.Home
	p := e.plan(t, sc, Selector{Rules: []string{"diagnostic-reports"}}, Options{Permanent: true, LookPath: yesLookPath})
	testutil.Build(t, h, testutil.Tree{"Documents/thesis.pdf": testutil.File{Size: 1}, "Documents/notes.txt": testutil.File{Size: 1}})
	reports := filepath.Join(h, "Library/Logs/DiagnosticReports")
	if err := os.RemoveAll(reports); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h, "Documents"), reports); err != nil {
		t.Fatal(err)
	}
	ex, _ := e.executor(t, nil)
	sum := ex.Execute(context.Background(), p)
	if sum.Deleted != 0 || sum.Skipped != 1 {
		t.Errorf("summary = %+v", sum)
	}
	for _, kept := range []string{"Documents/thesis.pdf", "Documents/notes.txt"} {
		if _, err := os.Lstat(filepath.Join(h, kept)); err != nil {
			t.Errorf("%s deleted through a swapped container: %v", kept, err)
		}
	}
}

func TestPlanSkipsRunningAppCaches(t *testing.T) {
	tree := devTree()
	tree["Library/Caches/com.google.Chrome/blob"] = testutil.File{Size: 2_000_000}
	e := newEnv(t, tree)
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{Rules: []string{"user-app-caches"}}, Options{LookPath: yesLookPath,
		RunningApps: map[string]bool{"com.google.chrome": true}})
	got := itemPaths(e, p)
	if _, ok := got["Library/Caches/com.google.Chrome"]; ok {
		t.Error("cache of a running app planned")
	}
	if _, ok := got["Library/Caches/com.example"]; !ok {
		t.Error("cache of a non-running app missing")
	}
	found := false
	for _, l := range p.Left {
		if strings.HasSuffix(l.Path, "com.google.Chrome") && strings.Contains(l.Reason, "is running") {
			found = true
		}
	}
	if !found {
		t.Errorf("running app not explained: %+v", p.Left)
	}
}

func TestPlanSnapshots(t *testing.T) {
	e := newEnv(t, devTree())
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{Rules: []string{"none"}}, Options{LookPath: yesLookPath, Snapshots: true})
	if len(p.Items) != 0 || len(p.Left) != 1 || !strings.Contains(p.Left[0].Reason, "no local Time Machine snapshots") {
		t.Errorf("no snapshots: %+v %+v", p.Items, p.Left)
	}
	sc.Snapshots = []macos.Snapshot{{Name: "com.apple.TimeMachine.2026-10-01-000000.local"}}
	p = e.plan(t, sc, Selector{Rules: []string{"none"}}, Options{LookPath: yesLookPath, Snapshots: true})
	if len(p.Items) != 1 || p.Items[0].RuleID != SnapshotsRuleID || p.Items[0].Command[0] != "tmutil" {
		t.Fatalf("snapshot plan = %+v", p.Items)
	}
	r := &fakeRunner{err: errors.New("exit status 1")}
	ex, _ := e.executor(t, r)
	sum := ex.Execute(context.Background(), p)
	if sum.Failed != 1 || !strings.Contains(sum.Outcomes[0].Reason, "sudo tmutil thinlocalsnapshots") {
		t.Errorf("failure hint missing: %+v", sum.Outcomes)
	}
	p = e.plan(t, sc, Selector{Rules: []string{"none"}}, Options{LookPath: yesLookPath, Snapshots: true, SkipNative: true})
	if len(p.Items) != 0 {
		t.Error("--skip-native still planned tmutil")
	}
}

func TestRunningOwner(t *testing.T) {
	roots := []string{"/u/library/caches/", "/u/library/containers/", "/u/library/group containers/", "/u/library/application support/"}
	running := map[string]bool{"com.tinyspeck.slackmacgap": true, "google chrome": true, "slack": true, "com.example.notes": true}
	for path, want := range map[string]string{
		"/u/Library/Application Support/Slack/Cache":                              "slack",
		"/u/Library/Application Support/Google/Chrome/Default/GPUCache":           "google chrome",
		"/u/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Caches":     "com.tinyspeck.slackmacgap",
		"/u/Library/Group Containers/ABCDE12345.com.example.notes/Library/Caches": "com.example.notes",
		"/u/Library/Application Support/discord/Cache":                            "",
		"/u/Library/Caches/com.example.other":                                     "",
		"/u/Documents/Slack":                                                      "",
	} {
		if got := runningOwner(path, roots, running); got != want {
			t.Errorf("%s: owner %q, want %q", path, got, want)
		}
	}
}

// TestXDGCacheContentCheck: ~/.cache/* is a wide glob any tool may use, so
// its folders get the .git/.env check; fixed ~/Library caches do not.
func TestXDGCacheContentCheck(t *testing.T) {
	e := newEnv(t, testutil.Tree{
		".cache/tool-with-repo/.git/HEAD":      testutil.File{Size: 1},
		".cache/tool-with-repo/blob":           testutil.File{Size: 100_000},
		".cache/plain-tool/blob":               testutil.File{Size: 100_000},
		"Library/Caches/com.example/.git/HEAD": testutil.File{Size: 1},
		"Library/Caches/com.example/blob":      testutil.File{Size: 100_000},
	})
	sc := e.scan(t)
	p := e.plan(t, sc, Selector{MaxTier: safety.TierCaution, Rules: []string{"xdg-cache", "user-app-caches"}}, Options{LookPath: yesLookPath})
	ex, _ := e.executor(t, nil)
	ex.Execute(context.Background(), p)
	h := e.s.Home
	if _, err := os.Lstat(filepath.Join(h, ".cache/tool-with-repo/.git/HEAD")); err != nil {
		t.Errorf("~/.cache folder with .git was removed: %v", err)
	}
	for _, gone := range []string{".cache/plain-tool", "Library/Caches/com.example"} {
		if _, err := os.Lstat(filepath.Join(h, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not cleaned", gone)
		}
	}
}
