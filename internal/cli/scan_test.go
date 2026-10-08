package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/scanner"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

// sweep runs the CLI in-process and returns stdout, stderr and the exit code.
func sweep(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	color.NoColor = true
	var out, errb bytes.Buffer
	cmd := newRootCmd("test", fakeDoctorDeps(macos.AccessGranted))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	code := run(context.Background(), cmd, &errb)
	return out.String(), errb.String(), code
}

func fixture(t *testing.T) *testutil.Sandbox {
	t.Helper()
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"web/package.json":                  testutil.File{Size: 100},
		"web/node_modules/react/index.js":   testutil.File{Size: 3_000_000},
		"web/node_modules/lodash/lodash.js": testutil.File{Size: 1_500_000},
		"videos/holiday.mov":                testutil.File{Size: 4_000_000},
		"videos/copy.mov":                   testutil.Hardlink{To: "videos/holiday.mov"},
		"vm/Docker.raw":                     testutil.Sparse{Size: 2_000_000_000},
		"notes.txt":                         testutil.File{Size: 10},
		"link":                              testutil.Symlink{Target: "videos"},
	})
	return s
}

func TestScanThenTop(t *testing.T) {
	s := fixture(t)
	before := testutil.Snapshot(t, s.Tree)

	out, stderr, code := sweep(t, "scan", s.Tree)
	if code != 0 {
		t.Fatalf("scan exit %d: %s", code, stderr)
	}
	for _, want := range []string{"Scanned", "On disk", "Hard links", "1 extra links", "Symlinks", "Largest under", "web", "videos", "Saved to ~/Library/Caches/sweep/last-scan.gob.gz"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q:\n%s", want, out)
		}
	}
	if stderr != "" {
		t.Errorf("stderr not empty when not a terminal: %q", stderr)
	}

	// The cache landed in the sandbox home, nowhere else.
	cachePath := cache.DefaultPath(s.Home)
	s.RequireInside(t, cachePath)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache not written to sandbox: %v", err)
	}

	out, _, code = sweep(t, "top", "-n", "3")
	if code != 0 {
		t.Fatalf("top exit %d", code)
	}
	for _, want := range []string{"Largest files", "holiday.mov", "react/index.js", "Largest directories", "node_modules"} {
		if !strings.Contains(out, want) {
			t.Errorf("top output missing %q:\n%s", want, out)
		}
	}
	// Sparse file: real allocation is tiny, so it must not top the list.
	if i, j := strings.Index(out, "Docker.raw"), strings.Index(out, "holiday.mov"); i >= 0 && i < j {
		t.Errorf("sparse Docker.raw ranked above a real 4 MB file:\n%s", out)
	}

	files, _, _ := sweep(t, "top", "--files")
	if strings.Contains(files, "Largest directories") {
		t.Error("--files still printed directories")
	}
	dirs, _, _ := sweep(t, "top", "--dirs")
	if strings.Contains(dirs, "Largest files") {
		t.Error("--dirs still printed files")
	}
	if _, _, code := sweep(t, "top", "--files", "--dirs"); code == 0 {
		t.Error("--files with --dirs should be rejected")
	}

	testutil.AssertUnchanged(t, s.Tree, before)
}

func TestScanJSON(t *testing.T) {
	s := fixture(t)
	out, _, code := sweep(t, "scan", s.Tree, "--json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got scanSummary
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Root != s.Tree || got.Stats.Files == 0 || got.Stats.HardLinksDeduped != 1 || got.CachePath != cache.DefaultPath(s.Home) {
		t.Errorf("unexpected summary: %+v", got)
	}

	out, _, _ = sweep(t, "top", "--json", "-n", "2")
	var top topOutput
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("invalid top JSON: %v\n%s", err, out)
	}
	if len(top.Files) != 2 || len(top.Dirs) == 0 || top.Files[0].Size < top.Files[1].Size {
		t.Errorf("unexpected top JSON: %+v", top)
	}
}

func TestScanTildeAndVerbose(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, testutil.Tree{"Library/Caches/app/blob": testutil.File{Size: 2_000_000}})
	out, _, code := sweep(t, "scan", "~/Library", "-v")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "Scanned ~/Library") || !strings.Contains(out, "apparent size") || !strings.Contains(out, "Walked") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestTopWithoutScan(t *testing.T) {
	testutil.NewSandbox(t)
	_, stderr, code := sweep(t, "top")
	if code != 1 || !strings.Contains(stderr, "run 'sweep scan' first") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestScanCancelledKeepsPreviousCache(t *testing.T) {
	s := fixture(t)
	if _, _, code := sweep(t, "scan", s.Tree); code != 0 {
		t.Fatal("initial scan failed")
	}
	cachePath := cache.DefaultPath(s.Home)
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = runScan(ctx, io.Discard, io.Discard, &globalOptions{}, s.Home, scanner.Options{Root: s.Tree})
	if err == nil || !strings.Contains(err.Error(), "previous saved scan was left unchanged") {
		t.Fatalf("err = %v", err)
	}
	after, err := os.ReadFile(cachePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Error("cancelled scan modified the saved cache")
	}
}

func TestScanErrors(t *testing.T) {
	s := testutil.NewSandbox(t)
	for _, args := range [][]string{
		{"scan", filepath.Join(s.Tree, "missing")},
		{"scan", "a", "b"},
		{"top", "-n", "0"},
	} {
		if _, _, code := sweep(t, args...); code == 0 {
			t.Errorf("%v succeeded, want failure", args)
		}
	}
}

func TestProgressLine(t *testing.T) {
	var buf bytes.Buffer
	orig := isTerminal
	t.Cleanup(func() { isTerminal = orig })

	isTerminal = func(io.Writer) bool { return false }
	p := newProgressLine(&buf)
	p.update(scanner.Progress{Files: 10, Current: "/x"})
	p.clear()
	if buf.Len() != 0 {
		t.Errorf("progress drawn to a non-terminal: %q", buf.String())
	}

	isTerminal = func(io.Writer) bool { return true }
	t.Setenv("TERM", "xterm")
	t.Setenv("COLUMNS", "60")
	p = newProgressLine(&buf)
	long := "/Users/someone/" + strings.Repeat("deep/", 30) + "end"
	p.update(scanner.Progress{Files: 1234, Bytes: 5_000_000, Current: long})
	line := buf.String()
	if !strings.Contains(line, "1,234 files") || !strings.Contains(line, "5.0 MB") || !strings.HasSuffix(line, "end") || !strings.Contains(line, "…") {
		t.Errorf("unexpected progress line %q", line)
	}
	buf.Reset()
	p.clear()
	if buf.String() != "\r\x1b[K" {
		t.Errorf("clear wrote %q", buf.String())
	}
}

func TestPathHelpers(t *testing.T) {
	if got := expandHome("~/a", "/h"); got != "/h/a" {
		t.Errorf("expandHome = %s", got)
	}
	if got := expandHome("~", "/h"); got != "/h" {
		t.Errorf("expandHome(~) = %s", got)
	}
	for in, want := range map[string]string{"/h": "~", "/h/x": "~/x", "/hx": "/hx", "/other": "/other"} {
		if got := shortPath(in, "/h"); got != want {
			t.Errorf("shortPath(%s) = %s, want %s", in, got, want)
		}
	}
}

func homeFixture(t *testing.T) *testutil.Sandbox {
	t.Helper()
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, testutil.Tree{
		"code/web/package.json":                testutil.File{Size: 10},
		"code/web/node_modules/react/index.js": testutil.File{Size: 3_000_000},
		"code/rs/Cargo.toml":                   testutil.File{Size: 10},
		"code/rs/target/debug/app":             testutil.File{Size: 2_000_000},
		"code/py/.venv/pyvenv.cfg":             testutil.File{Size: 10},
		"code/py/.venv/lib/torch.so":           testutil.File{Size: 1_500_000},
		"Library/Caches/com.example/blob":      testutil.File{Size: 1_200_000},
		"Library/Mobile Documents/doc.pages":   testutil.File{Size: 1_100_000},
		"Documents/thesis.pdf":                 testutil.File{Size: 10},
		".ssh/id_ed25519":                      testutil.File{Size: 10},
	})
	return s
}

func TestScanClassifiesAndTopShowsTiers(t *testing.T) {
	s := homeFixture(t)
	out, stderr, code := sweep(t, "scan", "~")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"By risk tier", "SAFE", "CAUTION", "PROTECTED", "never deleted"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q:\n%s", want, out)
		}
	}
	out, _, _ = sweep(t, "scan", "~", "--json")
	var sum scanSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatal(err)
	}
	totals := map[string]report.TierTotal{}
	for _, tt := range sum.Tiers {
		totals[tt.Tier.String()] = tt
	}
	// SAFE: node_modules, target, com.example, plus sweep's own cache written by the first scan.
	if totals["SAFE"].Count != 4 || totals["CAUTION"].Count != 1 || totals["PROTECTED"].Count != 1 {
		t.Errorf("tier totals = %+v", sum.Tiers)
	}

	out, _, _ = sweep(t, "top", "--dirs")
	if !strings.Contains(out, "TIER") || !regexpMatch(out, `SAFE\s+~/code/web/node_modules`) {
		t.Errorf("top --dirs missing tiers:\n%s", out)
	}
	_ = s
}

func TestRulesList(t *testing.T) {
	s := testutil.NewSandbox(t)
	out, _, code := sweep(t, "rules", "list")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"node-modules", "Dev: JavaScript", "rust-target", "docker-desktop-disk", "built-in"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}

	cfg := filepath.Join(s.Home, ".config", "sweep", "rules.yaml")
	testutil.Build(t, s.Home, testutil.Tree{".config/sweep/rules.yaml": testutil.File{Content: []byte(
		"rules:\n  - {id: my-tmp, category: Mine, match: {path: ~/tmp/junk}, tier: SAFE, description: scratch}\n")}})
	out, _, _ = sweep(t, "rules", "list", "--json")
	var rs []map[string]any
	if err := json.Unmarshal([]byte(out), &rs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rs {
		if r["id"] == "my-tmp" && r["user"] == true && r["source"] == cfg {
			found = true
		}
	}
	if !found {
		t.Errorf("user rule missing from JSON list")
	}
}

func TestConfigErrors(t *testing.T) {
	s := testutil.NewSandbox(t)
	write := func(body string) string {
		p := filepath.Join(s.Dir, "cfg.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"protected target": "rules:\n  - {id: k, category: C, match: {path: ~/.ssh}, tier: SAFE, description: d}\n",
		"unknown field":    "rules:\n  - {id: k, category: C, match: {pth: ~/x}, tier: SAFE, description: d}\n",
		"user command":     "rules:\n  - {id: k, category: C, match: {path: ~/x/y}, tier: SAFE, description: d, native_clean: [brew, cleanup]}\n",
	}
	for name, body := range cases {
		_, stderr, code := sweep(t, "rules", "list", "--config", write(body))
		if code == 0 || !strings.Contains(stderr, "cfg.yaml") {
			t.Errorf("%s: exit %d, stderr %q (want an error naming the file)", name, code, stderr)
		}
	}
	if _, stderr, code := sweep(t, "rules", "list", "--config", filepath.Join(s.Dir, "nope.yaml")); code == 0 {
		t.Errorf("missing explicit config accepted: %s", stderr)
	}
}

func TestExplainCommand(t *testing.T) {
	s := homeFixture(t)
	if _, _, code := sweep(t, "scan", "~"); code != 0 {
		t.Fatal("scan failed")
	}
	tests := []struct {
		path string
		want []string
	}{
		{"~/code/web/node_modules", []string{"SAFE", "node-modules", "package.json next to it", "npm install", "Included in 'sweep clean' by default", "scan from"}},
		{"~/code/web/node_modules/react/index.js", []string{"Inside", "~/code/web/node_modules", "as part of the enclosing match"}},
		{"~/code/py/.venv", []string{"CAUTION", "pyvenv.cfg inside", "only with 'sweep clean --tier caution'"}},
		{"~/Documents/thesis.pdf", []string{"REVIEW", "unclassified, likely user data", "Never cleaned automatically"}},
		{"~/.ssh/id_ed25519", []string{"PROTECTED", "SSH keys", "otherwise REVIEW", "likely user data", "Never deleted"}},
		{"~/Library/Mobile Documents", []string{"PROTECTED", "icloud-drive", "iCloud"}},
		{"~/code/nothing-here", []string{"does not exist"}},
	}
	for _, tt := range tests {
		out, stderr, code := sweep(t, "explain", tt.path)
		if code != 0 {
			t.Errorf("explain %s: exit %d %s", tt.path, code, stderr)
			continue
		}
		for _, w := range tt.want {
			if !strings.Contains(out, w) {
				t.Errorf("explain %s missing %q:\n%s", tt.path, w, out)
			}
		}
	}

	out, _, _ := sweep(t, "explain", "~/code/rs/target", "--json")
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["rule_id"] != "rust-target" || got["tier"] != "SAFE" || got["project_root"] != filepath.Join(s.Home, "code/rs") {
		t.Errorf("explain JSON = %v", got)
	}
}

func regexpMatch(s, pattern string) bool {
	return regexp.MustCompile(pattern).MatchString(s)
}

func TestReportCommand(t *testing.T) {
	homeFixture(t)
	if _, _, code := sweep(t, "report"); code != 1 {
		t.Error("report without a scan should fail")
	}
	if _, stderr, code := sweep(t, "scan", "~"); code != 0 {
		t.Fatalf("scan: %s", stderr)
	}
	out, stderr, code := sweep(t, "report")
	if code != 0 {
		t.Fatalf("report exit %d: %s", code, stderr)
	}
	for _, want := range []string{"sweep report", "1. Disk overview", "500.0 GB total", "Only ~ was scanned",
		"Where your space is going", "Dev: JavaScript", "System Data", "Reclaimable space",
		"~/code/web/node_modules", "Protected (for your information)", "Next steps", "sweep clean --tier safe --dry-run"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}

	out, _, _ = sweep(t, "report", "--json", "--top", "2")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if c, _ := rep["cleanup_candidates"].([]any); len(c) != 2 {
		t.Errorf("--top 2 gave %d candidates", len(c))
	}
	for _, key := range []string{"disk", "categories", "system_data", "tiers", "stale_projects", "review", "protected", "next_steps"} {
		if _, ok := rep[key]; !ok {
			t.Errorf("JSON missing %q", key)
		}
	}
}

func TestRulesSearchFoundAndShow(t *testing.T) {
	s := testutil.NewSandbox(t)
	out, _, _ := sweep(t, "rules")
	if !strings.Contains(out, "Run 'sweep scan' to see what each rule finds") {
		t.Errorf("no-scan hint missing:\n%s", out)
	}
	testutil.Build(t, s.Home, testutil.Tree{
		"code/web/package.json":                         testutil.File{Size: 10},
		"code/web/node_modules/r/i.js":                  testutil.File{Size: 2_000_000},
		"code/api/package.json":                         testutil.File{Size: 10},
		"code/api/node_modules/r/i.js":                  testutil.File{Size: 1_000_000},
		"Library/Application Support/Slack/Local State": testutil.File{Size: 10},
		"Library/Application Support/Slack/Cache/data":  testutil.File{Size: 500_000},
	})
	if _, stderr, code := sweep(t, "scan", "~"); code != 0 {
		t.Fatalf("scan: %s", stderr)
	}

	out, _, _ = sweep(t, "rules", "--found")
	for _, want := range []string{"node-modules", "chromium-http-cache", "(2)", "App caches", "rules shown", "Found"} {
		if !strings.Contains(out, want) {
			t.Errorf("--found missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rust-target") {
		t.Errorf("--found lists a rule that found nothing:\n%s", out)
	}

	out, _, _ = sweep(t, "rules", "electron", "--tier", "safe")
	if !strings.Contains(out, "chromium-http-cache") || strings.Contains(out, "node-modules") || strings.Contains(out, "chromium-service-worker-cache") {
		t.Errorf("search/tier filter wrong:\n%s", out)
	}
	if _, stderr, code := sweep(t, "rules", "--tier", "bogus"); code == 0 || !strings.Contains(stderr, "tier") {
		t.Errorf("bad tier accepted: %s", stderr)
	}

	out, _, code := sweep(t, "rules", "show", "node-modules", "-n", "1")
	if code != 0 {
		t.Fatalf("show exit %d", code)
	}
	for _, want := range []string{"Dev: JavaScript", "in 2 items", "~/code/web/node_modules", "1 more", "sweep clean --rule node-modules"} {
		if !strings.Contains(out, want) {
			t.Errorf("show missing %q:\n%s", want, out)
		}
	}
	if _, stderr, code := sweep(t, "rules", "show", "nope"); code == 0 || !strings.Contains(stderr, `no rule "nope"`) {
		t.Errorf("unknown rule: %s", stderr)
	}
}
