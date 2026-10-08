package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/audit"
	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/cleaner"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

// sweepIn runs the CLI with stdin. terminal makes stdin count as a terminal,
// as it would for a person typing answers.
func sweepIn(t *testing.T, stdin string, terminal bool, args ...string) (string, string, int) {
	t.Helper()
	color.NoColor = true
	orig := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return terminal }
	t.Cleanup(func() { stdinIsTerminal = orig })
	var out, errb bytes.Buffer
	cmd := newRootCmd("test", fakeDoctorDeps(macos.AccessGranted))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	code := run(context.Background(), cmd, &errb)
	return out.String(), errb.String(), code
}

func cleanFixture(t *testing.T) *testutil.Sandbox {
	t.Helper()
	s := testutil.NewSandbox(t)
	old := time.Now().Add(-200 * 24 * time.Hour)
	testutil.Build(t, s.Home, testutil.Tree{
		"code/web/package.json":           testutil.File{Size: 10},
		"code/web/node_modules/r/i.js":    testutil.File{Size: 2_000_000},
		"code/web/.next/cache/x":          testutil.File{Size: 1_500_000},
		"code/web/dist/bundle.js":         testutil.File{Size: 1_100_000},
		"code/old/package.json":           testutil.File{Size: 10, MTime: old},
		"code/old/node_modules/r/i.js":    testutil.File{Size: 1_200_000},
		"code/rs/Cargo.toml":              testutil.File{Size: 10},
		"code/rs/target/debug/app":        testutil.File{Size: 1_300_000},
		"code/py/.venv/pyvenv.cfg":        testutil.File{Size: 10},
		"code/py/.venv/lib/torch.so":      testutil.File{Size: 1_400_000},
		"Library/Caches/com.example/blob": testutil.File{Size: 1_000_000},
		"Library/Caches/go-build/aa":      testutil.File{Size: 1_000_000},
		"Documents/thesis.pdf":            testutil.File{Size: 1_000_000},
		".ssh/id_ed25519":                 testutil.File{Size: 10},
	})
	if _, stderr, code := sweep(t, "scan", "~"); code != 0 {
		t.Fatalf("scan: %s", stderr)
	}
	testRunner.take()
	return s
}

func exists(t *testing.T, s *testutil.Sandbox, rel string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(s.Home, rel))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func TestCleanDryRunChangesNothing(t *testing.T) {
	s := cleanFixture(t)
	before := testutil.Snapshot(t, s.Home+"/code")
	out, stderr, code := sweep(t, "clean", "--name", "node_modules", "--name", ".next")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	testutil.AssertUnchanged(t, s.Home+"/code", before)
	for _, want := range []string{"[DRY RUN]", "~/code/web/node_modules", "~/code/web/.next", "~/code/old/node_modules",
		"(stale project)", "move to Trash", "Dry run: nothing was changed.",
		"sweep clean --name node_modules --name .next --execute", "did not match your filters"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"code/web/dist", "code/rs/target"} {
		if strings.Contains(out, unwanted+" ") || strings.Contains(out, unwanted+"\n") {
			t.Errorf("filtered item %s in plan:\n%s", unwanted, out)
		}
	}
	if len(testRunner.take()) != 0 {
		t.Error("dry run ran a native command")
	}

	out, _, _ = sweep(t, "clean", "--json")
	var plan map[string]any
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("plan JSON: %v", err)
	}
	if items, _ := plan["items"].([]any); len(items) == 0 {
		t.Error("JSON plan has no items")
	}
	testutil.AssertUnchanged(t, s.Home+"/code", before)
}

func TestCleanNeedsConfirmation(t *testing.T) {
	s := cleanFixture(t)
	before := testutil.Snapshot(t, s.Home)

	_, stderr, code := sweepIn(t, "", false, "clean", "--execute")
	if code == 0 || !strings.Contains(stderr, "without confirmation") {
		t.Errorf("non-terminal without --yes: exit %d, %q", code, stderr)
	}
	_, stderr, code = sweepIn(t, "n\n", true, "clean", "--execute")
	if code == 0 || !strings.Contains(stderr, "not confirmed") {
		t.Errorf("answered n: exit %d, %q", code, stderr)
	}
	_, _, code = sweepIn(t, "\n", true, "clean", "--execute")
	if code == 0 {
		t.Error("empty answer must default to No")
	}
	testutil.AssertUnchanged(t, s.Home, before)
	if exists(t, s, "Library/Logs/sweep/history.jsonl") {
		t.Error("audit log written although nothing was confirmed")
	}
}

func TestCleanExecute(t *testing.T) {
	s := cleanFixture(t)
	out, stderr, code := sweepIn(t, "y\n", true, "clean", "--name", "node_modules", "--name", ".next", "--execute")
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, stderr, out)
	}
	if !strings.Contains(stderr, "Move 3 items") {
		t.Errorf("prompt = %q", stderr)
	}
	for _, gone := range []string{"code/web/node_modules", "code/web/.next", "code/old/node_modules"} {
		if exists(t, s, gone) {
			t.Errorf("%s not cleaned", gone)
		}
	}
	for _, kept := range []string{"code/web/package.json", "code/web/dist", "code/rs/target", "code/py/.venv",
		"Library/Caches/com.example", "Documents/thesis.pdf", ".ssh/id_ed25519"} {
		if !exists(t, s, kept) {
			t.Errorf("%s removed although not selected", kept)
		}
	}
	for _, inTrash := range []string{".Trash/node_modules", ".Trash/node_modules 2", ".Trash/.next"} {
		if !exists(t, s, inTrash) {
			t.Errorf("Trash missing %s", inTrash)
		}
	}
	for _, want := range []string{"✓", "Done: 3 moved to the Trash", "Audit log: ~/Library/Logs/sweep/history.jsonl", "restored from the Trash"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// Audit log in the sandbox, one line per item.
	f, err := os.Open(audit.DefaultPath(s.Home))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lines := 0
	for sc := bufio.NewScanner(f); sc.Scan(); lines++ {
	}
	if lines != 3 {
		t.Errorf("audit log has %d lines, want 3", lines)
	}

	// The saved scan forgets cleaned items: a second identical run plans nothing.
	saved, err := cache.Load(cache.DefaultPath(s.Home))
	if err != nil {
		t.Fatal(err)
	}
	if saved.CleanedItems != 3 {
		t.Errorf("CleanedItems = %d", saved.CleanedItems)
	}
	out, _, _ = sweep(t, "clean", "--name", "node_modules", "--name", ".next")
	if !strings.Contains(out, "Nothing selected") {
		t.Errorf("second run still plans cleaned items:\n%s", out)
	}
	out, _, _ = sweep(t, "report")
	if !strings.Contains(out, "3 items") || !strings.Contains(out, "cleaned since this scan") {
		t.Errorf("report does not mention the cleanup:\n%s", out)
	}
}

func TestCleanYesRunsNativeAndPermanent(t *testing.T) {
	s := cleanFixture(t)
	_, stderr, code := sweepIn(t, "", false, "clean", "--rule", "go-build-cache", "--rule", "rust-target", "--permanent", "--execute", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	calls := testRunner.take()
	if len(calls) != 1 || strings.Join(calls[0], " ") != "go clean -cache" {
		t.Errorf("native calls = %v", calls)
	}
	if exists(t, s, "code/rs/target") || exists(t, s, ".Trash/target") {
		t.Error("--permanent should delete target, not trash it")
	}
	if !exists(t, s, "Library/Caches/go-build/aa") {
		t.Error("sweep deleted go-build files itself instead of running go clean")
	}
}

func TestCleanInteractive(t *testing.T) {
	s := cleanFixture(t)
	// The plan lists node_modules (2.0 MB) first and .next (1.5 MB) second;
	// untoggle item 2, accept, then confirm.
	out, stderr, code := sweepIn(t, "2\n\ny\n", true, "clean", "--name", "node_modules", "--name", ".next", "--under", "~/code/web", "--interactive", "--execute")
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, stderr, out)
	}
	if exists(t, s, "code/web/node_modules") || !exists(t, s, "code/web/.next") {
		t.Errorf("interactive selection not honored")
	}

	_, _, code = sweepIn(t, "q\n", true, "clean", "--interactive", "--execute")
	if code == 0 {
		t.Error("q should cancel")
	}
	_, stderr, code = sweepIn(t, "", false, "clean", "--interactive")
	if code == 0 || !strings.Contains(stderr, "needs a terminal") {
		t.Errorf("--interactive without a terminal: %q", stderr)
	}
}

func TestCleanLargePlanNeedsTypedConfirmation(t *testing.T) {
	s := cleanFixture(t)
	orig := largePlanItems
	largePlanItems = 1
	t.Cleanup(func() { largePlanItems = orig })
	before := testutil.Snapshot(t, s.Home+"/code")

	_, stderr, code := sweepIn(t, "", false, "clean", "--execute", "--yes")
	if code == 0 || !strings.Contains(stderr, "large") {
		t.Errorf("large plan with --yes and no terminal: exit %d %q", code, stderr)
	}
	_, _, code = sweepIn(t, "y\n", true, "clean", "--execute", "--yes")
	if code == 0 {
		t.Error("large plan accepted plain y")
	}
	testutil.AssertUnchanged(t, s.Home+"/code", before)

	_, stderr, code = sweepIn(t, "DELETE\n", true, "clean", "--name", "node_modules", "--execute")
	if code != 0 || exists(t, s, "code/web/node_modules") {
		t.Errorf("typed DELETE: exit %d %q", code, stderr)
	}
}

func TestCleanFlagErrors(t *testing.T) {
	cleanFixture(t)
	for _, args := range [][]string{
		{"clean", "--tier", "review"},
		{"clean", "--tier", "protected"},
		{"clean", "--tier", "everything"},
		{"clean", "--older-than", "soon"},
		{"clean", "--min-size", "big"},
		{"clean", "--dry-run", "--execute"},
		{"clean", "--exclude", "relative/glob"},
		{"clean", "--name", "a/b"},
	} {
		if _, _, code := sweep(t, args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestParseAge(t *testing.T) {
	day := 24 * time.Hour
	for in, want := range map[string]time.Duration{"36h": 36 * time.Hour, "30d": 30 * day, "2w": 14 * day, "6m": 180 * day, "1y": 365 * day, "7D": 7 * day} {
		if got, err := parseAge(in); err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "30", "1.5d", "-3d", "3 months"} {
		if _, err := parseAge(bad); err == nil {
			t.Errorf("parseAge(%q) accepted", bad)
		}
	}
}

func TestToggle(t *testing.T) {
	sel := []bool{true, true, true, true, true}
	if err := toggle(sel, "1 3-4"); err != nil || sel[0] || !sel[1] || sel[2] || sel[3] || !sel[4] {
		t.Errorf("toggle = %v, %v", sel, err)
	}
	for _, bad := range []string{"0", "6", "4-2", "x", "1-"} {
		if err := toggle(sel, bad); err == nil {
			t.Errorf("toggle(%q) accepted", bad)
		}
	}
}

func TestLs(t *testing.T) {
	cleanFixture(t)
	out, stderr, code := sweep(t, "ls")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"~", "code/", "Library/", "CLEANABLE", "Findings here"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls missing %q:\n%s", want, out)
		}
	}

	out, _, _ = sweep(t, "ls", "~/code/web")
	for _, want := range []string{"~/code/web", "node_modules/", "SAFE", "sweep clean --under ~/code/web"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls ~/code/web missing %q:\n%s", want, out)
		}
	}

	out, _, _ = sweep(t, "ls", "~/code", "--depth", "2", "--json")
	var o lsOutput
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatal(err)
	}
	var sawDeep, sawNM bool
	for _, r := range o.Rows {
		if r.Depth == 1 {
			sawDeep = true
		}
		if r.Name == "node_modules" && r.Tier == "SAFE" && r.Cleanable == r.Size {
			sawNM = true
		}
	}
	if !sawDeep || !sawNM || o.Cleanable["SAFE"].Count == 0 {
		t.Errorf("ls --depth 2 JSON = %+v", o)
	}

	for path, want := range map[string]string{
		"~/code/web/node_modules":   "single SAFE finding",
		"~/code/web/node_modules/r": "inside",
		"/definitely/elsewhere":     "not inside the last scan",
	} {
		_, stderr, code := sweep(t, "ls", path)
		if code == 0 || !strings.Contains(stderr, want) {
			t.Errorf("ls %s: exit %d, %q (want %q)", path, code, stderr, want)
		}
	}
}

func TestSnapshotsInReportAndClean(t *testing.T) {
	cleanFixture(t)
	out, _, _ := sweep(t, "report")
	for _, want := range []string{"Time Machine local snapshots (2)", "sweep clean --snapshots"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	out, _, code := sweep(t, "clean", "--snapshots", "--rule", "nothing-else")
	if code != 0 || !strings.Contains(out, "$ tmutil thinlocalsnapshots / 999999999999999 4") {
		t.Errorf("snapshot plan:\n%s", out)
	}
	_, stderr, code := sweepIn(t, "", false, "clean", "--snapshots", "--rule", "nothing-else", "--execute", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if calls := testRunner.take(); len(calls) != 1 || calls[0][0] != "tmutil" {
		t.Errorf("calls = %v", calls)
	}
	// Snapshots are forgotten after thinning; a second plan has nothing to offer.
	out, _, _ = sweep(t, "clean", "--snapshots", "--rule", "nothing-else")
	if !strings.Contains(out, "no local Time Machine snapshots") {
		t.Errorf("second plan:\n%s", out)
	}
}

func TestCleanSkipsRunningApps(t *testing.T) {
	cleanFixture(t)
	orig := runningApps
	runningApps = func(context.Context) map[string]bool { return map[string]bool{"com.example": true} }
	t.Cleanup(func() { runningApps = orig })
	out, _, _ := sweep(t, "clean", "--rule", "user-app-caches")
	if !strings.Contains(out, "com.example is running; quit it") {
		t.Errorf("running app not reported:\n%s", out)
	}
}

func TestRestore(t *testing.T) {
	s := cleanFixture(t)
	if _, stderr, code := sweep(t, "restore"); code == 0 || !strings.Contains(stderr, "no audit log") {
		t.Errorf("restore before any clean: %q", stderr)
	}
	if _, stderr, code := sweepIn(t, "", false, "clean", "--name", "node_modules", "--execute", "--yes"); code != 0 {
		t.Fatal(stderr)
	}
	if exists(t, s, "code/web/node_modules") {
		t.Fatal("not cleaned")
	}
	// Something new now sits where one item used to be; it must not be overwritten.
	testutil.Build(t, s.Home, testutil.Tree{"code/old/node_modules/fresh": testutil.File{Size: 1}})

	out, _, code := sweep(t, "restore")
	if code != 0 || !strings.Contains(out, "ready") || !strings.Contains(out, "something already exists") || !strings.Contains(out, "Dry run") {
		t.Fatalf("restore plan:\n%s", out)
	}
	if exists(t, s, "code/web/node_modules") {
		t.Fatal("dry run restored something")
	}
	out, stderr, code := sweepIn(t, "y\n", true, "restore", "--execute")
	if code != 0 {
		t.Fatalf("restore: %s\n%s", stderr, out)
	}
	if !exists(t, s, "code/web/node_modules/r/i.js") {
		t.Error("node_modules not restored")
	}
	if !exists(t, s, "code/old/node_modules/fresh") || exists(t, s, "code/old/node_modules/r") {
		t.Error("existing item overwritten")
	}
	out, _, _ = sweep(t, "restore", "--list")
	if !strings.Contains(out, "SESSION") {
		t.Errorf("list:\n%s", out)
	}
	// The restored item is not offered again; the blocked one still is.
	out, _, _ = sweep(t, "restore")
	if strings.Contains(out, "code/web/node_modules") {
		t.Errorf("restored item offered again:\n%s", out)
	}
}

func TestRestoreRejectsTamperedLog(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, testutil.Tree{"Documents/secret.txt": testutil.File{Size: 1}})
	line := `{"action":"trash","result":"ok","session":"s1","path":"` + s.Home + `/elsewhere/secret.txt","trash_path":"` + s.Home + `/Documents/secret.txt"}` + "\n"
	testutil.Build(t, s.Home, testutil.Tree{"Library/Logs/sweep/history.jsonl": testutil.File{Content: []byte(line)}})
	out, _, _ := sweep(t, "restore")
	if !strings.Contains(out, "does not point into the Trash") {
		t.Errorf("tampered entry not rejected:\n%s", out)
	}
	if _, _, code := sweepIn(t, "", false, "restore", "--execute", "--yes"); code == 0 {
		t.Error("restore of a tampered entry succeeded")
	}
	if !exists(t, s, "Documents/secret.txt") {
		t.Error("file moved by a tampered log entry")
	}
}

// TestCleanOldVersions: old nvm Node versions and Claude Code releases are
// cleaned, the versions in use are kept, and the re-check right before
// deleting sees a version that became current after the scan.
func TestCleanOldVersions(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, testutil.Tree{
		".nvm/alias/default":                   testutil.File{Content: []byte("22")},
		".nvm/versions/node/v18.20.0/bin/node": testutil.File{Size: 1_000_000},
		".nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 1_000_000},
		".nvm/versions/node/v22.23.2/bin/node": testutil.File{Size: 1_000_000},
		".local/share/claude/versions/2.1.282": testutil.File{Size: 1_000_000},
		".local/share/claude/versions/2.1.294": testutil.File{Size: 1_000_000},
		".local/bin/claude":                    testutil.Symlink{Target: "../share/claude/versions/2.1.294"},
	})
	t.Setenv("NVM_BIN", "")
	if _, stderr, code := sweep(t, "scan", "~"); code != 0 {
		t.Fatalf("scan: %s", stderr)
	}
	out, _, _ := sweep(t, "clean", "--tier", "caution", "--rule", "nvm-old-node-versions", "--rule", "claude-code-old-versions")
	for _, want := range []string{"v18.20.0", "v20.11.1", "2.1.282"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "v22.23.2") || strings.Contains(out, "2.1.294") {
		t.Errorf("plan includes a version in use:\n%s", out)
	}

	// v20 becomes the default after the scan: it must be kept.
	if err := os.WriteFile(filepath.Join(s.Home, ".nvm/alias/default"), []byte("20"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, _ := sweepIn(t, "", false, "clean", "--tier", "caution", "--rule", "nvm-old-node-versions",
		"--rule", "claude-code-old-versions", "--execute", "--yes")
	for _, gone := range []string{".nvm/versions/node/v18.20.0", ".local/share/claude/versions/2.1.282"} {
		if exists(t, s, gone) {
			t.Errorf("%s not cleaned:\n%s%s", gone, out, stderr)
		}
	}
	for _, kept := range []string{".nvm/versions/node/v20.11.1", ".nvm/versions/node/v22.23.2", ".local/share/claude/versions/2.1.294"} {
		if !exists(t, s, kept) {
			t.Errorf("%s removed although in use", kept)
		}
	}
	if !strings.Contains(out, "no longer matched") {
		t.Errorf("expected v20.11.1 to be skipped on re-check:\n%s", out)
	}
}

func TestRenderLeftGroupsByReason(t *testing.T) {
	color.NoColor = true
	var left []cleaner.Left
	for i := range 5 {
		left = append(left, cleaner.Left{Path: fmt.Sprintf("/h/c%d", i), Size: uint64(i+1) * 1000, Reason: "CAUTION item; add --tier caution to include it"})
	}
	left = append(left, cleaner.Left{Path: "/h/app", Size: 10, Reason: "Slack is running; quit it and run clean again"})
	var b bytes.Buffer
	renderLeft(&b, left, "/h", false)
	out := b.String()
	for _, want := range []string{"~/c4", "~/c2", "… 2 more like this", "3.0 kB", "~/app"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "~/c0") || strings.Index(out, "~/c4") > strings.Index(out, "~/app") {
		t.Errorf("wrong grouping or order:\n%s", out)
	}
	b.Reset()
	renderLeft(&b, left, "/h", true)
	if !strings.Contains(b.String(), "~/c0") || strings.Contains(b.String(), "more like this") {
		t.Errorf("--verbose should list all:\n%s", b.String())
	}
}
