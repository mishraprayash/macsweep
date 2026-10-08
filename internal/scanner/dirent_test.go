package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

func richTree() testutil.Tree {
	old := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	tree := testutil.Synthetic(15, 40, 3*kB)
	extras := testutil.Tree{
		"big.bin":              testutil.File{Size: 2 * MB, MTime: old},
		"empty":                testutil.File{Size: 0},
		"sparse.raw":           testutil.Sparse{Size: 300 * MB},
		"hard1":                testutil.Hardlink{To: "big.bin"},
		"d/hard2":              testutil.Hardlink{To: "big.bin"},
		"link-dir":             testutil.Symlink{Target: "d"},
		"link-file":            testutil.Symlink{Target: "big.bin"},
		"dangling":             testutil.Symlink{Target: "nowhere"},
		"unicodé/ファイル.txt":     testutil.File{Size: 10},
		"spaces in name/x y.z": testutil.File{Size: 10},
		"locked/secret":        testutil.File{Size: 10},
		"locked":               testutil.Dir{Mode: 0o000, Chmod: true},
		"emptydir":             testutil.Dir{},
		"d/.hidden":            testutil.File{Size: 5},
	}
	for k, v := range extras {
		tree[k] = v
	}
	return tree
}

// TestFastReadDirMatchesPortable: getattrlistbulk must report exactly what
// readdir + lstat report, entry by entry.
func TestFastReadDirMatchesPortable(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, richTree())
	var dirs []string
	_ = filepath.WalkDir(s.Tree, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	for _, dir := range dirs {
		fast, ferr := readDirFast(dir)
		slow, serr := readDirPortable(dir)
		if (ferr == nil) != (serr == nil) {
			t.Errorf("%s: fast err %v, portable err %v", dir, ferr, serr)
			continue
		}
		sort.Slice(fast, func(i, j int) bool { return fast[i].name < fast[j].name })
		sort.Slice(slow, func(i, j int) bool { return slow[i].name < slow[j].name })
		if len(fast) != len(slow) {
			t.Errorf("%s: %d entries fast, %d portable", dir, len(fast), len(slow))
			continue
		}
		for i := range fast {
			f, p := fast[i], slow[i]
			if f.name != p.name || f.isDir != p.isDir || f.isLink != p.isLink || f.dev != p.dev || f.ino != p.ino ||
				f.size != p.size || !f.mtime.Equal(p.mtime) || (f.err == nil) != (p.err == nil) {
				t.Errorf("%s/%s:\n fast     %+v\n portable %+v", dir, f.name, f, p)
			}
			if !f.isDir && f.err == nil && (f.alloc != p.alloc || f.nlink != p.nlink) {
				t.Errorf("%s/%s: alloc/nlink fast %d/%d portable %d/%d", dir, f.name, f.alloc, f.nlink, p.alloc, p.nlink)
			}
		}
	}
}

// TestScanSameWithEitherReader: whole scans agree, including totals.
func TestScanSameWithEitherReader(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, richTree())
	fast := scan(t, Options{Root: s.Tree})
	orig := listDirImpl
	listDirImpl = func(_ int, _, path string) (int, []dirent, error) {
		ents, err := readDirPortable(path)
		return -1, ents, err
	}
	t.Cleanup(func() { listDirImpl = orig })
	slow := scan(t, Options{Root: s.Tree})
	if fast.Stats != slow.Stats {
		t.Errorf("stats differ:\n fast     %+v\n portable %+v", fast.Stats, slow.Stats)
	}
	if len(fast.TopFiles) != len(slow.TopFiles) || fast.TopFiles[0] != slow.TopFiles[0] {
		t.Errorf("top files differ")
	}
}

func TestFastReadDirErrors(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{"f": testutil.File{Size: 1}, "l": testutil.Symlink{Target: "."}})
	for _, p := range []string{filepath.Join(s.Tree, "missing"), filepath.Join(s.Tree, "f"), filepath.Join(s.Tree, "l")} {
		if _, err := readDirFast(p); err == nil {
			t.Errorf("readDirFast(%s) succeeded", p)
		}
	}
	if _, err := Scan(context.Background(), Options{Root: filepath.Join(s.Tree, "missing")}); err == nil {
		t.Error("scan of missing root succeeded")
	}
}

func BenchmarkReadDir(b *testing.B) {
	s := testutil.NewSandbox(b)
	tree := testutil.Tree{}
	for i := 0; i < 2000; i++ {
		tree[filepath.Join("d", "f"+itoa(i))] = testutil.File{Size: 100}
	}
	testutil.Build(b, s.Tree, tree)
	dir := filepath.Join(s.Tree, "d")
	for _, impl := range []struct {
		name string
		fn   readDirFunc
	}{{"fast", readDirFast}, {"portable", readDirPortable}} {
		b.Run(impl.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := impl.fn(dir); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func itoa(i int) string {
	return string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
}
