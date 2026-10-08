package testutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Entry is something Build can create.
type Entry interface {
	kind() int // creation order: files/dirs, then links, then dir modes
}

// File is a regular file with Size bytes of content (or Content if set).
type File struct {
	Size    int64
	Content []byte
	Mode    fs.FileMode // default 0o644
	MTime   time.Time   // zero leaves it at creation time
}

// Sparse is a file whose apparent size is Size but which only has a few
// bytes actually written at the end, so it allocates almost nothing.
type Sparse struct{ Size int64 }

// Dir is an explicit directory. Directories are also created implicitly for
// the parents of any entry.
type Dir struct {
	// Mode is applied after all entries exist, but only when Chmod is set
	// (so that 0o000 is expressible). Otherwise the directory is 0o755.
	Mode  fs.FileMode
	Chmod bool
	MTime time.Time
}

// Symlink points at Target, which is resolved relative to the link's
// directory and must stay inside the tree root.
type Symlink struct{ Target string }

// Hardlink is another name for the tree entry at To (relative to root).
type Hardlink struct{ To string }

func (File) kind() int     { return 0 }
func (Sparse) kind() int   { return 0 }
func (Dir) kind() int      { return 0 }
func (Hardlink) kind() int { return 1 }
func (Symlink) kind() int  { return 1 }

// Tree maps slash-separated paths (relative to the root) to entries.
type Tree map[string]Entry

// Build creates tree under root. Every path must be local to root. Restricted
// directory modes are restored in t.Cleanup so the temp dir can be removed.
func Build(t testing.TB, root string, tree Tree) {
	t.Helper()
	paths := make([]string, 0, len(tree))
	for p := range tree {
		if !filepath.IsLocal(p) {
			t.Fatalf("testutil.Build: %q escapes the tree root", p)
		}
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		ki, kj := tree[paths[i]].kind(), tree[paths[j]].kind()
		if ki != kj {
			return ki < kj
		}
		return paths[i] < paths[j]
	})

	type pending struct {
		path string
		d    Dir
	}
	var dirs []pending
	for _, p := range paths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		switch e := tree[p].(type) {
		case File:
			buildFile(t, full, e)
		case Sparse:
			buildSparse(t, full, e)
		case Dir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			dirs = append(dirs, pending{full, e})
		case Hardlink:
			if !filepath.IsLocal(e.To) {
				t.Fatalf("testutil.Build: hardlink %q target %q escapes root", p, e.To)
			}
			if err := os.Link(filepath.Join(root, filepath.FromSlash(e.To)), full); err != nil {
				t.Fatal(err)
			}
		case Symlink:
			target := e.Target
			resolved := target
			if !filepath.IsAbs(target) {
				resolved = filepath.Join(filepath.Dir(full), target)
			}
			if !within(filepath.Clean(resolved), root) {
				t.Fatalf("testutil.Build: symlink %q target %q points outside the tree", p, target)
			}
			if err := os.Symlink(target, full); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("testutil.Build: unknown entry %T", e)
		}
	}

	// Deepest first, so restricting a parent doesn't block its children.
	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i].path, "/") > strings.Count(dirs[j].path, "/")
	})
	for _, d := range dirs {
		if !d.d.MTime.IsZero() {
			if err := os.Chtimes(d.path, d.d.MTime, d.d.MTime); err != nil {
				t.Fatal(err)
			}
		}
		if d.d.Chmod {
			path := d.path
			if err := os.Chmod(path, d.d.Mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
		}
	}
}

func buildFile(t testing.TB, full string, e File) {
	t.Helper()
	data := e.Content
	if data == nil {
		data = make([]byte, e.Size)
		for i := range data {
			data[i] = byte(i) // non-zero content so the FS can't elide blocks
		}
	}
	mode := e.Mode
	if mode == 0 {
		mode = 0o644
	}
	if err := os.WriteFile(full, data, mode); err != nil {
		t.Fatal(err)
	}
	if !e.MTime.IsZero() {
		if err := os.Chtimes(full, e.MTime, e.MTime); err != nil {
			t.Fatal(err)
		}
	}
}

func buildSparse(t testing.TB, full string, e Sparse) {
	t.Helper()
	f, err := os.Create(full)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt([]byte("end"), e.Size-3); err != nil {
		t.Fatal(err)
	}
}

// Synthetic returns a tree with dirs×files files of fileSize bytes, spread
// over two levels, for benchmarks and concurrency tests.
func Synthetic(dirs, filesPerDir int, fileSize int64) Tree {
	tree := Tree{}
	for d := 0; d < dirs; d++ {
		for f := 0; f < filesPerDir; f++ {
			tree[fmt.Sprintf("d%03d/sub%d/f%04d.bin", d, d%7, f)] = File{Size: fileSize}
		}
	}
	return tree
}
