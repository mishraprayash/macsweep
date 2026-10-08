// Package testutil provides the sandbox every sweep test runs in.
//
// The guarantees, so tests cannot touch the real disk:
//   - NewSandbox puts all state in t.TempDir() and points $HOME (and the XDG
//     dirs) at a fake home inside it, so anything that resolves the home
//     directory (cache, config, audit log) lands in the sandbox.
//   - It refuses to run if the temp dir is inside the real home directory.
//   - Build only creates entries inside the given root and rejects paths that
//     escape it ("..", absolute paths, symlinks pointing outside).
//   - Snapshot/AssertUnchanged prove an operation left a tree untouched.
//   - AssertReadOnlyPackage statically rejects mutating filesystem calls in
//     packages that must only read (scanner, report, …).
package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realHome is captured before any test can override $HOME.
var realHome = func() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(h); err == nil {
		return r
	}
	return h
}()

// Sandbox is an isolated directory tree for one test.
type Sandbox struct {
	// Dir is the sandbox root. Everything a test creates lives below it.
	Dir string
	// Home is the fake home directory. $HOME points here.
	Home string
	// Tree is an empty directory for fixture trees.
	Tree string
}

// NewSandbox creates a sandbox and redirects $HOME into it for the duration
// of the test. Tests using it cannot call t.Parallel (t.Setenv forbids it).
func NewSandbox(t testing.TB) *Sandbox {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	if realHome != "" && within(dir, realHome) {
		t.Fatalf("sandbox: temp dir %s is inside the real home %s; refusing to run", dir, realHome)
	}
	s := &Sandbox{Dir: dir, Home: filepath.Join(dir, "home"), Tree: filepath.Join(dir, "tree")}
	for _, d := range []string{s.Home, s.Tree} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("sandbox: %v", err)
		}
	}
	t.Setenv("HOME", s.Home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(s.Home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(s.Home, ".cache"))
	t.Setenv("NO_COLOR", "1")
	return s
}

// Path joins rel onto the sandbox root, failing the test if rel would escape it.
func (s *Sandbox) Path(t testing.TB, rel string) string {
	t.Helper()
	if !filepath.IsLocal(rel) {
		t.Fatalf("sandbox: %q is not a local path", rel)
	}
	return filepath.Join(s.Dir, rel)
}

// RequireInside fails the test unless path is inside the sandbox.
func (s *Sandbox) RequireInside(t testing.TB, path string) {
	t.Helper()
	if !within(path, s.Dir) {
		t.Fatalf("sandbox: %s is outside the sandbox %s", path, s.Dir)
	}
}

// RealHome returns the real home directory captured at startup, for tests
// that need to assert they never touched it.
func RealHome() string { return realHome }

func within(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}
