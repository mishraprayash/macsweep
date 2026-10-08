package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

const (
	kB = 1000
	MB = 1000 * kB
)

func scan(t *testing.T, opts Options) *Result {
	t.Helper()
	res, err := Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan(%s): %v", opts.Root, err)
	}
	return res
}

// lstatAlloc is the independent oracle: allocated bytes of one path.
func lstatAlloc(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(fi.Sys().(*syscall.Stat_t).Blocks) * 512
}

func TestScannerIsReadOnly(t *testing.T) {
	testutil.AssertReadOnlyPackage(t, ".")
}

func TestScanLeavesTreeUntouched(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"a/b/c.txt":           testutil.File{Size: 10 * kB},
		"a/link":              testutil.Symlink{Target: "b"},
		"a/hard":              testutil.Hardlink{To: "a/b/c.txt"},
		"proj/node_modules/x": testutil.File{Size: 1},
		"sparse.raw":          testutil.Sparse{Size: 50 * MB},
	})
	before := testutil.Snapshot(t, s.Tree)
	scan(t, Options{Root: s.Tree, Visit: func(e Entry) bool { return e.Name == "node_modules" }})
	testutil.AssertUnchanged(t, s.Tree, before)
}

func TestSizesMatchLstat(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"one.bin":       testutil.File{Size: 1},
		"a/two.bin":     testutil.File{Size: 5 * kB},
		"a/b/three.bin": testutil.File{Size: 2 * MB},
		"a/b/empty":     testutil.File{Size: 0},
	})
	res := scan(t, Options{Root: s.Tree})

	var want uint64
	err := filepath.WalkDir(s.Tree, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		want += lstatAlloc(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Size != want {
		t.Errorf("Size = %d, want %d (sum of st_blocks*512)", res.Stats.Size, want)
	}
	if res.Stats.ApparentSize < 1+5*kB+2*MB {
		t.Errorf("ApparentSize = %d, want >= file lengths", res.Stats.ApparentSize)
	}
	if res.Stats.Files != 4 || res.Stats.Dirs != 2 {
		t.Errorf("Files=%d Dirs=%d, want 4 and 2", res.Stats.Files, res.Stats.Dirs)
	}
	a := res.Tree.Find(filepath.Join(s.Tree, "a"))
	if a == nil || a.FileCount != 3 || a.DirCount != 1 {
		t.Fatalf("node a = %+v, want FileCount 3, DirCount 1", a)
	}
	if b := res.Tree.Find(filepath.Join(s.Tree, "a", "b")); b == nil || b.Size > a.Size {
		t.Errorf("child b larger than parent a")
	}
}

// TestMatchesDu cross-checks the total against the system du(1).
func TestMatchesDu(t *testing.T) {
	if _, err := exec.LookPath("du"); err != nil {
		t.Skip("du not available")
	}
	s := testutil.NewSandbox(t)
	tree := testutil.Synthetic(20, 15, 3*kB)
	tree["big.bin"] = testutil.File{Size: 3 * MB}
	tree["h1"] = testutil.Hardlink{To: "big.bin"}
	tree["sparse"] = testutil.Sparse{Size: 100 * MB}
	testutil.Build(t, s.Tree, tree)

	res := scan(t, Options{Root: s.Tree})
	out, err := exec.Command("du", "-sk", s.Tree).Output()
	if err != nil {
		t.Fatal(err)
	}
	duKiB, err := strconv.ParseUint(strings.Fields(string(out))[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Stats.Size / 1024; got != duKiB {
		t.Errorf("scanner %d KiB, du %d KiB", got, duKiB)
	}
}

func TestHardLinksCountedOnce(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"a/orig.bin": testutil.File{Size: 1 * MB},
		"b/link1":    testutil.Hardlink{To: "a/orig.bin"},
		"c/d/link2":  testutil.Hardlink{To: "a/orig.bin"},
	})
	res := scan(t, Options{Root: s.Tree})
	one := lstatAlloc(t, filepath.Join(s.Tree, "a", "orig.bin"))
	var dirs uint64
	for _, d := range []string{"", "a", "b", "c", "c/d"} {
		dirs += lstatAlloc(t, filepath.Join(s.Tree, d))
	}
	if res.Stats.Size != one+dirs {
		t.Errorf("Size = %d, want %d (file counted once + dirs)", res.Stats.Size, one+dirs)
	}
	if res.Stats.HardLinksDeduped != 2 || res.Stats.Files != 1 {
		t.Errorf("HardLinksDeduped=%d Files=%d, want 2 and 1", res.Stats.HardLinksDeduped, res.Stats.Files)
	}
}

func TestSymlinksNotFollowed(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Dir, testutil.Tree{
		"elsewhere/big.bin":    testutil.File{Size: 5 * MB},
		"tree/link-to-dir":     testutil.Symlink{Target: "../elsewhere"},
		"tree/link-to-file":    testutil.Symlink{Target: "../elsewhere/big.bin"},
		"tree/dangling":        testutil.Symlink{Target: "nope"},
		"tree/self/loop":       testutil.Symlink{Target: "."},
		"tree/self/regular.go": testutil.File{Size: 10},
	})
	res := scan(t, Options{Root: s.Tree})
	if res.Stats.Size >= 5*MB {
		t.Errorf("Size = %d: symlink target was counted", res.Stats.Size)
	}
	if res.Stats.Symlinks != 4 {
		t.Errorf("Symlinks = %d, want 4", res.Stats.Symlinks)
	}
	if res.Stats.Dirs != 1 {
		t.Errorf("Dirs = %d, want 1 (only self/)", res.Stats.Dirs)
	}
	for _, f := range res.TopFiles {
		if strings.Contains(f.Path, "elsewhere") || strings.Contains(f.Path, "link-to-dir/") {
			t.Errorf("followed a symlink: %s", f.Path)
		}
	}
}

func TestSparseFileUsesAllocatedSize(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{"Docker.raw": testutil.Sparse{Size: 1000 * MB}})
	res := scan(t, Options{Root: s.Tree})
	if len(res.TopFiles) != 1 {
		t.Fatalf("TopFiles = %v", res.TopFiles)
	}
	f := res.TopFiles[0]
	if f.ApparentSize != 1000*MB {
		t.Errorf("ApparentSize = %d, want %d", f.ApparentSize, 1000*MB)
	}
	if f.Size >= 10*MB {
		t.Errorf("allocated Size = %d; sparse file should allocate almost nothing", f.Size)
	}
	if res.Stats.Size >= 10*MB {
		t.Errorf("total Size = %d counts apparent size", res.Stats.Size)
	}
}

func TestPermissionDeniedRecordedAndSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"ok/visible.bin":  testutil.File{Size: 100 * kB},
		"locked/hidden":   testutil.File{Size: 100 * kB},
		"locked":          testutil.Dir{Mode: 0o000, Chmod: true},
		"zz/after.bin":    testutil.File{Size: 100 * kB},
		"partial/a/x.bin": testutil.File{Size: 1},
		"partial/a":       testutil.Dir{Mode: 0o300, Chmod: true}, // can enter, cannot list
	})
	res := scan(t, Options{Root: s.Tree, Workers: 1})
	if res.Stats.Inaccessible != 2 {
		t.Errorf("Inaccessible = %d, want 2 (%v)", res.Stats.Inaccessible, res.Inaccessible)
	}
	want := map[string]bool{filepath.Join(s.Tree, "locked"): true, filepath.Join(s.Tree, "partial", "a"): true}
	for _, p := range res.Inaccessible {
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("missing inaccessible paths %v in %v", want, res.Inaccessible)
	}
	if n := res.Tree.Find(filepath.Join(s.Tree, "locked")); n == nil || !n.Inaccessible {
		t.Errorf("locked node not marked inaccessible: %+v", n)
	}
	if res.Stats.Files != 2 {
		t.Errorf("Files = %d, want 2 (scan must continue past the locked dir)", res.Stats.Files)
	}
}

func TestPrune(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{
		"app/package.json":                     testutil.File{Size: 10},
		"app/node_modules/react/index.js":      testutil.File{Size: 50 * kB},
		"app/node_modules/react/lib/deep.js":   testutil.File{Size: 50 * kB},
		"app/node_modules/.bin/tool":           testutil.File{Size: 1},
		"app/node_modules/nested/node_modules": testutil.Dir{},
	})
	var calls atomic.Int32
	var fileVisits atomic.Int32
	res := scan(t, Options{Root: s.Tree, Visit: func(e Entry) bool {
		if !e.IsDir {
			fileVisits.Add(1)
			return true // ignored for files
		}
		calls.Add(1)
		return e.Name == "node_modules"
	}})
	nm := res.Tree.Find(filepath.Join(s.Tree, "app", "node_modules"))
	if nm == nil {
		t.Fatal("node_modules node missing")
	}
	if !nm.Pruned || nm.Children != nil {
		t.Errorf("node_modules: Pruned=%v Children=%d, want pruned with no children", nm.Pruned, len(nm.Children))
	}
	if nm.FileCount != 3 || nm.DirCount != 5 || nm.Size < 100*kB {
		t.Errorf("node_modules totals: files=%d dirs=%d size=%d", nm.FileCount, nm.DirCount, nm.Size)
	}
	if calls.Load() != 2 {
		t.Errorf("Visit called for %d dirs, want 2 (app, app/node_modules; not inside pruned)", calls.Load())
	}
	if fileVisits.Load() != 1 {
		t.Errorf("visited %d files, want 1 (package.json; nothing inside node_modules)", fileVisits.Load())
	}
}

func TestTopFiles(t *testing.T) {
	s := testutil.NewSandbox(t)
	tree := testutil.Tree{}
	for i := 1; i <= 30; i++ {
		tree["f"+strconv.Itoa(i)] = testutil.File{Size: int64(i) * 10 * kB}
	}
	testutil.Build(t, s.Tree, tree)
	res := scan(t, Options{Root: s.Tree, TopFiles: 5, Workers: 8})
	if len(res.TopFiles) != 5 {
		t.Fatalf("len(TopFiles) = %d, want 5", len(res.TopFiles))
	}
	for i, want := range []string{"f30", "f29", "f28", "f27", "f26"} {
		if filepath.Base(res.TopFiles[i].Path) != want {
			t.Errorf("TopFiles[%d] = %s, want %s", i, res.TopFiles[i].Path, want)
		}
	}
}

// TestConcurrencyDeterministic: any worker count gives identical totals.
func TestConcurrencyDeterministic(t *testing.T) {
	s := testutil.NewSandbox(t)
	tree := testutil.Synthetic(40, 25, 2*kB)
	tree["d000/hl"] = testutil.Hardlink{To: "d001/sub1/f0000.bin"}
	testutil.Build(t, s.Tree, tree)

	base := scan(t, Options{Root: s.Tree, Workers: 1})
	for _, w := range []int{2, 7, 64, 512} {
		got := scan(t, Options{Root: s.Tree, Workers: w})
		if got.Stats.Size != base.Stats.Size || got.Stats.Files != base.Stats.Files ||
			got.Stats.Dirs != base.Stats.Dirs || got.Stats.HardLinksDeduped != base.Stats.HardLinksDeduped {
			t.Errorf("workers=%d: %+v, want %+v", w, got.Stats, base.Stats)
		}
		if got.Tree.DirCount != base.Tree.DirCount || got.Tree.FileCount != base.Tree.FileCount {
			t.Errorf("workers=%d: tree counts differ", w)
		}
	}
	if base.Stats.Files != 40*25 {
		t.Errorf("Files = %d, want %d", base.Stats.Files, 40*25)
	}
}

func TestCancellation(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Synthetic(200, 1, 1)) // 400 directories

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, Options{Root: s.Tree}); !errors.Is(err, context.Canceled) {
		t.Errorf("pre-cancelled: err = %v, want context.Canceled", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var seen atomic.Int32
	_, err := Scan(ctx, Options{Root: s.Tree, Workers: 4, Visit: func(e Entry) bool {
		if !e.IsDir {
			return false
		}
		if seen.Add(1) == 10 {
			cancel()
		}
		return false
	}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled mid-scan: err = %v, want context.Canceled", err)
	}
	// Cancellation must stop the walk promptly, not merely report it at the end.
	if n := seen.Load(); n > 50 {
		t.Errorf("visited %d of 400 directories after cancelling at 10", n)
	}
}

func TestProgress(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Synthetic(10, 10, 1))
	var last Progress
	var calls int
	res := scan(t, Options{Root: s.Tree, ProgressInterval: time.Millisecond, Progress: func(p Progress) {
		calls++ // callbacks are serialised: one goroutine, then the final call after it exits
		last = p
	}})
	if calls == 0 {
		t.Fatal("progress never called")
	}
	if last.Files != res.Stats.Files || last.Dirs != res.Stats.Dirs {
		t.Errorf("final progress %+v does not match stats %+v", last, res.Stats)
	}
}

func TestBadRoots(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Tree, testutil.Tree{"file": testutil.File{Size: 1}})
	for _, root := range []string{"", "relative", filepath.Join(s.Tree, "missing"), filepath.Join(s.Tree, "file")} {
		if _, err := Scan(context.Background(), Options{Root: root}); err == nil {
			t.Errorf("Scan(%q) succeeded, want error", root)
		}
	}
}

func TestSymlinkRootResolvedOnce(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Dir, testutil.Tree{
		"real/x.bin": testutil.File{Size: 1 * kB},
		"alias":      testutil.Symlink{Target: "real"},
	})
	res := scan(t, Options{Root: filepath.Join(s.Dir, "alias")})
	if res.Root != filepath.Join(s.Dir, "real") || res.Stats.Files != 1 {
		t.Errorf("Root=%s Files=%d, want resolved root with 1 file", res.Root, res.Stats.Files)
	}
}

// buildFakeDisk lays out a miniature macOS disk: a system volume whose
// /Users and /usr/local are firmlinks into System/Volumes/Data. Firmlinks
// can't be created in a test, so they are symlinks here. The scanner never
// follows symlinks, so the firmlink skip list and the data-volume walk are
// what get exercised.
func buildFakeDisk(t *testing.T, root string) {
	testutil.Build(t, root, testutil.Tree{
		"usr/share/firmlinks":           testutil.File{Content: []byte("/Users\tUsers\n/usr/local\tusr/local\n/Volumes\tVolumes\n")},
		"usr/bin/ls":                    testutil.File{Size: 100 * kB},
		"System/Library/Kernels/kernel": testutil.File{Size: 300 * kB},
		"Users":                         testutil.Symlink{Target: "System/Volumes/Data/Users"},
		"System/Volumes/Data/Users/alice/big.mov":        testutil.File{Size: 2 * MB},
		"System/Volumes/Data/Users/alice/Library/c.db":   testutil.File{Size: 500 * kB},
		"System/Volumes/Data/usr/local/bin/tool":         testutil.File{Size: 50 * kB},
		"System/Volumes/Data/private/var/log/system.log": testutil.File{Size: 20 * kB},
		"System/Volumes/Data/Volumes/External/huge.iso":  testutil.File{Size: 5 * MB},
		"System/Volumes/Preboot/junk.bin":                testutil.File{Size: 4 * MB},
		"Volumes/Backup/huge.bin":                        testutil.File{Size: 6 * MB},
		"dev/null-ish":                                   testutil.File{Size: 1 * MB},
	})
	// On the system volume, these paths would be firmlinks: create real
	// directories there to prove they are skipped rather than counted twice.
	testutil.Build(t, root, testutil.Tree{
		"usr/local/bin/tool": testutil.File{Size: 50 * kB},
	})
}

func TestWholeDiskFirmlinks(t *testing.T) {
	s := testutil.NewSandbox(t)
	disk := s.Tree
	buildFakeDisk(t, disk)
	res := scan(t, Options{Root: disk, FSRoot: disk})

	if len(res.Walks) != 2 || res.Walks[1].Path != filepath.Join(disk, DataVolumeRel) || res.Walks[1].DisplayAs != disk {
		t.Fatalf("walks = %+v", res.Walks)
	}

	// Data-volume paths are reported in user-facing form.
	alice := res.Tree.Find(filepath.Join(disk, "Users", "alice"))
	if alice == nil || alice.Size < 2500*kB {
		t.Fatalf("/Users/alice missing or too small: %+v", alice)
	}
	if res.Tree.Find(filepath.Join(disk, DataVolumeRel)) != nil {
		t.Error("data volume appears under its physical path; it should be mapped back")
	}

	// /usr exists on both volumes and is merged; /usr/local counted once.
	local := res.Tree.Find(filepath.Join(disk, "usr", "local"))
	if local == nil || local.FileCount != 1 {
		t.Errorf("/usr/local = %+v, want exactly one file (no double count)", local)
	}
	usr := res.Tree.Find(filepath.Join(disk, "usr"))
	if usr == nil || usr.FileCount != 3 { // firmlinks, ls, tool
		t.Errorf("/usr FileCount = %+v, want 3", usr)
	}

	var files []string
	for _, f := range res.TopFiles {
		files = append(files, f.Path)
	}
	joined := strings.Join(files, "\n")
	for _, bad := range []string{"huge.iso", "junk.bin", "huge.bin", "null-ish", "System/Volumes"} {
		if strings.Contains(joined, bad) {
			t.Errorf("counted skipped content %q:\n%s", bad, joined)
		}
	}
	for _, want := range []string{"Users/alice/big.mov", "usr/bin/ls", "System/Library/Kernels/kernel", "private/var/log/system.log"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in top files:\n%s", want, joined)
		}
	}

	// 7 real files plus the /Users symlink standing in for the firmlink.
	if len(res.TopFiles) != 7 || res.Stats.Files != 8 || res.Stats.Symlinks != 1 {
		t.Errorf("Files = %d (top=%d), want 7: %s", res.Stats.Files, len(res.TopFiles), joined)
	}
	if res.Tree.FileCount != res.Stats.Files {
		t.Errorf("tree FileCount %d != stats Files %d", res.Tree.FileCount, res.Stats.Files)
	}

	reasons := map[string]bool{}
	for _, sk := range res.Skipped {
		reasons[strings.TrimPrefix(sk.Path, disk)] = true
	}
	for _, want := range []string{"/System/Volumes", "/usr/local", "/Volumes", "/dev"} {
		if !reasons[want] {
			t.Errorf("expected %s in skipped list: %+v", want, res.Skipped)
		}
	}
}

func TestDataVolumeSubpathMapped(t *testing.T) {
	s := testutil.NewSandbox(t)
	buildFakeDisk(t, s.Tree)
	res := scan(t, Options{Root: filepath.Join(s.Tree, DataVolumeRel, "Users"), FSRoot: s.Tree})
	if res.Root != filepath.Join(s.Tree, "Users") {
		t.Errorf("Root = %s, want user-facing %s", res.Root, filepath.Join(s.Tree, "Users"))
	}
	if len(res.TopFiles) == 0 || !strings.HasPrefix(res.TopFiles[0].Path, filepath.Join(s.Tree, "Users")+"/") {
		t.Errorf("top file paths not mapped: %+v", res.TopFiles)
	}
}

func TestNonRootScanIgnoresFirmlinkPlan(t *testing.T) {
	s := testutil.NewSandbox(t)
	buildFakeDisk(t, s.Tree)
	res := scan(t, Options{Root: filepath.Join(s.Tree, "usr"), FSRoot: s.Tree})
	if len(res.Walks) != 1 {
		t.Errorf("walks = %+v, want a single walk", res.Walks)
	}
}

func TestDevOfMatchesSafetyFileID(t *testing.T) {
	s := testutil.NewSandbox(t)
	fi, err := os.Lstat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	dev, _, ok := safety.FileID(fi)
	if !ok || dev != devOf(fi.Sys().(*syscall.Stat_t)) {
		t.Errorf("devOf and safety.FileID disagree")
	}
}

func BenchmarkScan(b *testing.B) {
	s := testutil.NewSandbox(b)
	testutil.Build(b, s.Tree, testutil.Synthetic(200, 50, 512)) // 10k files, 1.4k dirs
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Scan(context.Background(), Options{Root: s.Tree}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestVisitEntries(t *testing.T) {
	s := testutil.NewSandbox(t)
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	testutil.Build(t, s.Tree, testutil.Tree{
		"d/f.bin": testutil.File{Size: 5 * kB, MTime: old},
		"d/h":     testutil.Hardlink{To: "d/f.bin"},
	})
	var mu sync.Mutex
	got := map[string]Entry{}
	res := scan(t, Options{Root: s.Tree, Visit: func(e Entry) bool {
		mu.Lock()
		defer mu.Unlock()
		got[e.Path] = e
		return false
	}})
	if len(got) != 2 {
		t.Fatalf("visited %d entries, want 2 (d and one name of the hard-linked file): %v", len(got), got)
	}
	d := got[filepath.Join(s.Tree, "d")]
	if !d.IsDir || d.Name != "d" || d.Ino == 0 {
		t.Errorf("dir entry = %+v", d)
	}
	var f Entry
	for _, e := range got {
		if !e.IsDir {
			f = e
		}
	}
	if f.Size == 0 || f.ApparentSize != 5*kB || !f.MTime.Equal(old) || f.Ino == 0 {
		t.Errorf("file entry = %+v", f)
	}
	if n := res.Tree.Find(filepath.Join(s.Tree, "d")); n == nil || !n.OwnNewest.Equal(old) {
		t.Errorf("OwnNewest = %v, want %v", n.OwnNewest, old)
	}
}
