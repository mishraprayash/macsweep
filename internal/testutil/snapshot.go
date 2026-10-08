package testutil

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// EntryState is what Snapshot records for each path. Access time is left
// out on purpose: reading a file may legitimately update it.
type EntryState struct {
	Mode  fs.FileMode
	Size  int64
	MTime time.Time
	Ino   uint64
	Link  string // symlink target
}

// Snapshot records the state of every entry under root without following
// symlinks. Unreadable directories are recorded but not descended.
func Snapshot(t testing.TB, root string) map[string]EntryState {
	t.Helper()
	out := map[string]EntryState{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil // recorded via its own Lstat below when reached as an entry
			}
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := EntryState{Mode: fi.Mode(), Size: fi.Size(), MTime: fi.ModTime()}
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			st.Ino = sys.Ino
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			st.Link, _ = os.Readlink(p)
		}
		out[p] = st
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// AssertUnchanged fails the test if anything under root was added, removed,
// or modified since before was taken.
func AssertUnchanged(t testing.TB, root string, before map[string]EntryState) {
	t.Helper()
	after := Snapshot(t, root)
	var diffs []string
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			diffs = append(diffs, "removed: "+p)
		case a != b:
			diffs = append(diffs, "modified: "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			diffs = append(diffs, "added: "+p)
		}
	}
	if len(diffs) > 0 {
		sort.Strings(diffs)
		t.Fatalf("tree %s changed:\n  %s", root, strings.Join(diffs, "\n  "))
	}
}

// mutating lists filesystem-changing functions in os, syscall, and
// golang.org/x/sys/unix.
var mutating = map[string]bool{
	"Remove": true, "RemoveAll": true, "Rename": true, "Renameat": true,
	"WriteFile": true, "Create": true, "CreateTemp": true, "OpenFile": true,
	"Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "Mkdirat": true,
	"Chmod": true, "Fchmod": true, "Chown": true, "Lchown": true, "Fchown": true,
	"Chtimes": true, "Utimes": true, "UtimesNano": true, "Truncate": true, "Ftruncate": true,
	"Link": true, "Symlink": true, "Unlink": true, "Unlinkat": true, "Rmdir": true,
	"Setxattr": true, "Removexattr": true, "Exchangedata": true, "Clonefile": true,
}

// AssertReadOnlyPackage parses the non-test Go files in dir and fails if any
// calls a mutating os/syscall/unix function or imports os/exec. Use it for
// packages that must never modify the filesystem.
func AssertReadOnlyPackage(t testing.TB, dir string) {
	t.Helper()
	fset := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range matches {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		watched := map[string]bool{}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := filepath.Base(path)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			switch path {
			case "os", "syscall", "golang.org/x/sys/unix":
				watched[name] = true
			case "os/exec":
				t.Errorf("%s imports os/exec; read-only packages must not run commands", file)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && watched[id.Name] && mutating[sel.Sel.Name] {
				t.Errorf("%s: %s.%s mutates the filesystem; this package must be read-only",
					fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatalf("AssertReadOnlyPackage: no Go files in %s", dir)
	}
}
