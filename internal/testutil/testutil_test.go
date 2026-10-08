package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSandboxRedirectsHome(t *testing.T) {
	s := NewSandbox(t)
	h, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if h != s.Home {
		t.Errorf("UserHomeDir = %s, want sandbox home %s", h, s.Home)
	}
	if RealHome() != "" && within(s.Dir, RealHome()) {
		t.Errorf("sandbox %s is inside the real home", s.Dir)
	}
}

// fatalRecorder captures Fatalf instead of failing the real test.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = format
	runtime.Goexit()
}

func (f *fatalRecorder) Helper() {}

func expectFatal(t *testing.T, fn func(tb testing.TB)) string {
	t.Helper()
	rec := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(rec)
	}()
	<-done
	if rec.msg == "" {
		t.Fatal("expected a fatal error, got none")
	}
	return rec.msg
}

func TestBuildRejectsEscapes(t *testing.T) {
	s := NewSandbox(t)
	cases := []Tree{
		{"../outside": File{Size: 1}},
		{"/etc/evil": File{Size: 1}},
		{"a/../../x": File{Size: 1}},
		{"link": Symlink{Target: "/"}},
		{"link": Symlink{Target: "../../.."}},
		{"hl": Hardlink{To: "../x"}},
	}
	for _, tree := range cases {
		expectFatal(t, func(tb testing.TB) { Build(tb, s.Tree, tree) })
	}
	if _, err := os.Lstat(filepath.Join(s.Dir, "outside")); err == nil {
		t.Error("escaping file was created")
	}
	expectFatal(t, func(tb testing.TB) { s.Path(tb, "../x") })
}

func TestSnapshotDetectsChanges(t *testing.T) {
	s := NewSandbox(t)
	Build(t, s.Tree, Tree{"a/f": File{Size: 3}, "b": Symlink{Target: "a"}})
	before := Snapshot(t, s.Tree)

	AssertUnchanged(t, s.Tree, before) // no change: passes

	if err := os.WriteFile(filepath.Join(s.Tree, "a", "new"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	msg := expectFatal(t, func(tb testing.TB) { AssertUnchanged(tb, s.Tree, before) })
	if !strings.Contains(msg, "changed") {
		t.Errorf("unexpected message %q", msg)
	}
}

func TestReadOnlyCheckCatchesMutations(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import (
	fs "os"
	"syscall"
)
func f() { _ = fs.RemoveAll("never-run"); _ = syscall.Unlink("never-run"); _, _ = fs.ReadDir(".") }
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &errorRecorder{TB: t}
	AssertReadOnlyPackage(rec, dir)
	if rec.n != 2 {
		t.Errorf("flagged %d calls, want 2 (RemoveAll via alias, Unlink)", rec.n)
	}
}

type errorRecorder struct {
	testing.TB
	n int
}

func (e *errorRecorder) Errorf(string, ...any) { e.n++ }
func (e *errorRecorder) Helper()               {}
