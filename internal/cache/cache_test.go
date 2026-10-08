package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{"a/b/f.bin": testutil.File{Size: 2_000_000}, "c/g": testutil.File{Size: 10}})
	res, err := scanner.Scan(context.Background(), scanner.Options{Root: s.Tree})
	if err != nil {
		t.Fatal(err)
	}
	path := DefaultPath(s.Home)
	s.RequireInside(t, path)
	findings := []classifier.Finding{{Path: "/x/node_modules", RuleID: "node-modules", Tier: safety.TierSafe, Size: 42, Dev: 7, Ino: 99}}
	if err := Save(path, &Scan{Result: res, Findings: findings}); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.Result
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "node-modules" || loaded.Findings[0].Tier != safety.TierSafe || loaded.Findings[0].Ino != 99 {
		t.Errorf("findings not preserved: %+v", loaded.Findings)
	}
	if got.Root != res.Root || got.Stats != res.Stats || len(got.TopFiles) != len(res.TopFiles) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got.Stats, res.Stats)
	}
	if n := got.Tree.Find(filepath.Join(s.Tree, "a", "b")); n == nil || n.Size != res.Tree.Find(filepath.Join(s.Tree, "a", "b")).Size {
		t.Error("tree not preserved")
	}
	if !got.FinishedAt.Equal(res.FinishedAt) {
		t.Error("timestamps not preserved")
	}

	// Only the cache file remains: the temp file was renamed into place.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Errorf("unexpected files in cache dir: %v", entries)
	}
}

func TestLoadErrors(t *testing.T) {
	s := testutil.NewSandbox(t)
	if _, err := Load(filepath.Join(s.Dir, "missing.gob.gz")); !errors.Is(err, ErrNoScan) {
		t.Errorf("missing: err = %v, want ErrNoScan", err)
	}
	bad := filepath.Join(s.Dir, "bad.gob.gz")
	if err := os.WriteFile(bad, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || errors.Is(err, ErrNoScan) {
		t.Errorf("corrupt: err = %v", err)
	}
}

func TestSaveFailureLeavesNoTempFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
	s := testutil.NewSandbox(t)
	dir := filepath.Join(s.Dir, "ro")
	testutil.Build(t, s.Dir, testutil.Tree{"ro": testutil.Dir{Mode: 0o500, Chmod: true}})
	if err := Save(filepath.Join(dir, "last-scan.gob.gz"), &Scan{Result: &scanner.Result{Tree: &scanner.Node{Name: "/"}}}); err == nil {
		t.Fatal("Save into read-only dir succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("left files behind: %v", entries)
	}
}
