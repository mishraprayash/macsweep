// Package scanner walks a filesystem tree concurrently and measures it.
//
// The scanner is strictly read-only: it only opens and lists directories.
// On macOS it lists with getattrlistbulk(2) (many entries per system call,
// subdirectories opened relative to their parent); elsewhere, and on
// filesystems without that call, with readdir + lstat. TestScannerIsReadOnly
// enforces read-only access by rejecting any mutating os, syscall or unix
// call in this package's non-test source.
//
// Sizes are allocated bytes (blocks on disk), so sparse files such as
// Docker.raw report their real on-disk usage. Hard links are counted once
// per (device, inode), symlinks are never followed, and device boundaries
// are not crossed unless asked.
package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// DataVolumeRel is the APFS data volume relative to the filesystem root.
	DataVolumeRel = "System/Volumes/Data"
	// FirmlinksRel lists the system-volume paths firmlinked to the data volume.
	FirmlinksRel = "usr/share/firmlinks"

	maxRecorded = 1000
)

// DefaultWorkers is 2×CPU cores, clamped to [4, 32]. Measured on an
// 8-core M-series Mac scanning 2.2 M files: 4×cores was 40% slower and used
// twice the system CPU (kernel contention); 1×cores left the SSD idle.
func DefaultWorkers() int { return min(max(runtime.NumCPU()*2, 4), 32) }

// Options configures a scan.
type Options struct {
	// Root is the directory to scan (absolute).
	Root string
	// FSRoot is the filesystem root, normally "/". Tests point it at a
	// fixture tree to exercise whole-disk (firmlink) handling.
	FSRoot string
	// Workers bounds concurrent directory reads. Default DefaultWorkers().
	Workers int
	// CrossDevice allows descending into other mounted filesystems (network
	// filesystems are still skipped).
	CrossDevice bool
	// TopFiles is how many of the largest files to keep. Default 1000.
	TopFiles int
	// Visit, if set, is called for every directory (before it is read) and
	// every counted file, except inside pruned directories. It may be called
	// from many goroutines at once. Returning true for a directory prunes it:
	// it is fully sized, but its contents are not visited or kept in the tree.
	Visit func(e Entry) (prune bool)
	// Progress, if set, is called periodically from a separate goroutine.
	Progress func(Progress)
	// ProgressInterval defaults to 100ms (~10 updates/sec).
	ProgressInterval time.Duration
}

// Entry describes a visited file or directory. For directories, sizes are
// not yet known (they are in the tree once the scan completes).
type Entry struct {
	Path         string
	Name         string
	IsDir        bool
	Size         uint64 // allocated bytes (files only)
	ApparentSize uint64 // st_size (files only)
	MTime        time.Time
	Dev, Ino     uint64
}

// Progress is a snapshot of a running scan.
type Progress struct {
	Files   uint64
	Dirs    uint64
	Bytes   uint64
	Current string
	Elapsed time.Duration
}

// Stats summarises a scan.
type Stats struct {
	Files            uint64 `json:"files"`
	Dirs             uint64 `json:"dirs"`
	Symlinks         uint64 `json:"symlinks"`
	HardLinksDeduped uint64 `json:"hard_links_deduped"`
	Inaccessible     uint64 `json:"inaccessible"`
	Errors           uint64 `json:"errors"`
	Size             uint64 `json:"size_bytes"`
	ApparentSize     uint64 `json:"apparent_size_bytes"`
}

// Skip records a directory deliberately not descended into.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Walk records one physical walk and the user-facing path it maps to.
type Walk struct {
	Path      string `json:"path"`
	DisplayAs string `json:"display_as"`
}

// Result is a completed scan.
type Result struct {
	Root       string      `json:"root"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Workers    int         `json:"workers"`
	Walks      []Walk      `json:"walks"`
	Stats      Stats       `json:"stats"`
	Tree       *Node       `json:"-"`
	TopFiles   []FileEntry `json:"top_files"`
	// Inaccessible and Errors hold the first maxRecorded paths. Stats has
	// the full counts.
	Inaccessible []string `json:"inaccessible"`
	Errors       []string `json:"errors"`
	Skipped      []Skip   `json:"skipped"`
}

type walkSpec struct {
	real, display string
	skip          map[string]string // display path → reason
}

// Scan walks opts.Root and returns its measurements. It honors ctx
// cancellation and returns ctx.Err() if cancelled.
func Scan(ctx context.Context, opts Options) (*Result, error) {
	if opts.Root == "" || !filepath.IsAbs(opts.Root) {
		return nil, fmt.Errorf("scan root must be an absolute path, got %q", opts.Root)
	}
	if opts.FSRoot == "" {
		opts.FSRoot = "/"
	}
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers()
	}
	if opts.TopFiles == 0 {
		opts.TopFiles = 1000
	}
	if opts.ProgressInterval <= 0 {
		opts.ProgressInterval = 100 * time.Millisecond
	}

	root, err := resolveRoot(filepath.Clean(opts.Root))
	if err != nil {
		return nil, err
	}
	specs := planWalks(root, filepath.Clean(opts.FSRoot))

	w := &walker{
		ctx:  ctx,
		opts: opts,
		sem:  make(chan struct{}, opts.Workers-1),
		top:  newTopFiles(opts.TopFiles),
		seen: make(map[fileKey]struct{}),
	}
	res := &Result{Root: specs[0].display, StartedAt: time.Now(), Workers: opts.Workers}

	stopProgress := w.startProgress(res.StartedAt)
	for _, s := range specs {
		res.Walks = append(res.Walks, Walk{Path: s.real, DisplayAs: s.display})
		n, err := w.walkRoot(s)
		if err != nil {
			stopProgress()
			return nil, err
		}
		if res.Tree == nil {
			res.Tree = n
		} else {
			mergeInto(res.Tree, n)
		}
	}
	stopProgress()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res.FinishedAt = time.Now()
	res.TopFiles = w.top.sorted()
	res.Inaccessible = w.inaccessible
	res.Errors = w.errors
	res.Skipped = w.skipped
	res.Stats = Stats{
		Files:            w.files.Load(),
		Dirs:             w.dirs.Load(),
		Symlinks:         w.symlinks.Load(),
		HardLinksDeduped: w.dedup.Load(),
		Inaccessible:     w.inacc.Load(),
		Errors:           w.errs.Load(),
		Size:             res.Tree.Size,
		ApparentSize:     res.Tree.ApparentSize,
	}
	return res, nil
}

func resolveRoot(root string) (string, error) {
	fi, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("scan root: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		// The root is an explicit user argument, so resolve it once (e.g.
		// /tmp → /private/tmp). Nothing below it is ever followed.
		if root, err = filepath.EvalSymlinks(root); err != nil {
			return "", fmt.Errorf("scan root: %w", err)
		}
		if fi, err = os.Lstat(root); err != nil {
			return "", fmt.Errorf("scan root: %w", err)
		}
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("scan root %s is not a directory", root)
	}
	return root, nil
}

// planWalks decides what to walk. Scanning the filesystem root on macOS
// would double-count user data, because the sealed system volume and the
// data volume are joined by firmlinks (and report the same device). So:
// walk the system volume skipping /System/Volumes and every firmlinked path,
// then walk the data volume once and map its paths back to their user-facing
// form (/System/Volumes/Data/Users → /Users).
func planWalks(root, fsroot string) []walkSpec {
	dv := filepath.Join(fsroot, DataVolumeRel)
	if root != fsroot || !isDir(dv) {
		display := root
		if rel, ok := strings.CutPrefix(root, dv+"/"); ok {
			display = filepath.Join(fsroot, rel)
		} else if root == dv {
			display = fsroot
		}
		return []walkSpec{{real: root, display: display}}
	}

	at := func(rel string) string { return joinPath(fsroot, rel) }
	common := map[string]string{
		at("Volumes"):        "mount points for other disks",
		at("dev"):            "device files",
		at("net"):            "network automount",
		at("home"):           "network automount",
		at("System/Volumes"): "other APFS volumes (data volume is scanned separately)",
	}
	sys := map[string]string{}
	for k, v := range common {
		sys[k] = v
	}
	for _, f := range readFirmlinks(filepath.Join(fsroot, FirmlinksRel)) {
		sys[at(f)] = "firmlink to the data volume (counted there)"
	}
	data := map[string]string{}
	for k, v := range common {
		data[k] = v
	}
	return []walkSpec{
		{real: fsroot, display: fsroot, skip: sys},
		{real: dv, display: fsroot, skip: data},
	}
}

// readFirmlinks parses /usr/share/firmlinks ("/Users\tUsers" per line) and
// returns the firmlinked paths relative to the root.
func readFirmlinks(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if rel := strings.Trim(fields[0], "/"); rel != "" {
			out = append(out, rel)
		}
	}
	return out
}

func isDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

type fileKey struct{ dev, ino uint64 }

type walker struct {
	ctx  context.Context
	opts Options
	sem  chan struct{}
	top  *topFiles

	files, dirs, bytes, symlinks, dedup, inacc, errs atomic.Uint64
	current                                          atomic.Pointer[string]

	mu           sync.Mutex
	seen         map[fileKey]struct{}
	inaccessible []string
	errors       []string
	skipped      []Skip
}

func (w *walker) walkRoot(s walkSpec) (*Node, error) {
	d, err := lstatDirent(s.real)
	if err != nil {
		return nil, fmt.Errorf("scan root: %w", err)
	}
	n := newNode(s.display, &d)
	w.bytes.Add(n.Size)
	w.walkDir(-1, s.real, s.display, n, d.dev, s.skip, false)
	return n, nil
}

func newNode(name string, d *dirent) *Node {
	return &Node{Name: name, Size: d.alloc, ApparentSize: d.size, MTime: d.mtime, ATime: d.atime}
}

func allocated(st *syscall.Stat_t) uint64 { return uint64(max(st.Blocks, 0)) * 512 }

func devOf(st *syscall.Stat_t) uint64 {
	return uint64(uint32(st.Dev)) //nolint:gosec // matches safety.FileID encoding
}

// listDirImpl opens and lists a directory; tests swap it to compare
// implementations. parent is the open descriptor of the parent directory
// (or -1); the returned descriptor is passed to the children, then closed.
var listDirImpl = listDirFast

// walkDir measures one directory into n. n is owned by the calling
// goroutine; children are handed to other goroutines only before they are
// read here, after wg.Wait.
func (w *walker) walkDir(parent int, real, display string, n *Node, dev uint64, skip map[string]string, pruned bool) {
	if w.ctx.Err() != nil {
		return
	}
	w.current.Store(&display)

	fd, entries, err := listDirImpl(parent, n.Name, real)
	if err != nil {
		w.recordErr(display, n, err) // keep any entries read before the error
	}
	// Children open themselves relative to fd, so it stays open until they
	// are done (wg.Wait below).
	defer closeDir(fd)

	var wg sync.WaitGroup
	var children []*Node
	for i := range entries {
		d := &entries[i]
		if d.err != nil {
			w.recordErr(joinPath(display, d.name), n, d.err)
			continue
		}

		if d.isDir {
			if w.ctx.Err() != nil {
				break // cancelled: stop queueing siblings
			}
			childReal, childDisplay := joinPath(real, d.name), joinPath(display, d.name)
			if reason, ok := skip[childDisplay]; ok {
				w.addSkip(childDisplay, reason)
				continue
			}
			if d.dev != dev {
				if !w.opts.CrossDevice {
					w.addSkip(childDisplay, "different filesystem (use --cross-device to include)")
					continue
				}
				if networkFS(childReal) {
					w.addSkip(childDisplay, "network filesystem")
					continue
				}
			}
			c := newNode(d.name, d)
			childPruned := pruned
			if !pruned && w.opts.Visit != nil && w.opts.Visit(Entry{
				Path: childDisplay, Name: d.name, IsDir: true, MTime: d.mtime, Dev: d.dev, Ino: d.ino,
			}) {
				c.Pruned, childPruned = true, true
			}
			children = append(children, c)
			w.dirs.Add(1)
			w.bytes.Add(c.Size)
			childDev := d.dev
			select {
			case w.sem <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-w.sem }()
					w.walkDir(fd, childReal, childDisplay, c, childDev, skip, childPruned)
				}()
			default:
				w.walkDir(fd, childReal, childDisplay, c, childDev, skip, childPruned)
			}
			continue
		}

		if d.isLink {
			w.symlinks.Add(1)
		}
		if d.nlink > 1 && !w.firstLink(d.dev, d.ino) {
			w.dedup.Add(1)
			continue
		}
		n.Size += d.alloc
		n.ApparentSize += d.size
		n.FileCount++
		if d.mtime.After(n.Newest) {
			n.Newest = d.mtime
			n.OwnNewest = d.mtime
		}
		w.files.Add(1)
		w.bytes.Add(d.alloc)
		// Paths are built only when needed: most files are neither among the
		// largest nor visited (inside pruned directories).
		wantTop, visit := w.top.wants(d.alloc), !pruned && w.opts.Visit != nil
		if !wantTop && !visit {
			continue
		}
		childDisplay := joinPath(display, d.name)
		if wantTop {
			w.top.offer(FileEntry{Path: childDisplay, Size: d.alloc, ApparentSize: d.size, MTime: d.mtime, ATime: d.atime})
		}
		if visit {
			w.opts.Visit(Entry{
				Path: childDisplay, Name: d.name, Size: d.alloc, ApparentSize: d.size, MTime: d.mtime, Dev: d.dev, Ino: d.ino,
			})
		}
	}
	wg.Wait()

	for _, c := range children {
		n.Size += c.Size
		n.ApparentSize += c.ApparentSize
		n.FileCount += c.FileCount
		n.DirCount += 1 + c.DirCount
		if c.Newest.After(n.Newest) {
			n.Newest = c.Newest
		}
	}
	if n.Pruned {
		return
	}
	n.Children = children
	sortChildren(n)
	if pruned {
		// Inside a pruned subtree: totals are kept, structure is not.
		n.Children = nil
	}
}

// firstLink reports whether this (dev, inode) is being seen for the first
// time. Only called for files with more than one link.
func (w *walker) firstLink(dev, ino uint64) bool {
	k := fileKey{dev, ino}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.seen[k]; ok {
		return false
	}
	w.seen[k] = struct{}{}
	return true
}

func (w *walker) recordErr(path string, parent *Node, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Vanished mid-scan; nothing to count.
		return
	case errors.Is(err, fs.ErrPermission):
		parent.Inaccessible = true
		w.inacc.Add(1)
		w.mu.Lock()
		if len(w.inaccessible) < maxRecorded {
			w.inaccessible = append(w.inaccessible, path)
		}
		w.mu.Unlock()
	default:
		parent.Inaccessible = true
		w.errs.Add(1)
		w.mu.Lock()
		if len(w.errors) < maxRecorded {
			w.errors = append(w.errors, fmt.Sprintf("%s: %v", path, err))
		}
		w.mu.Unlock()
	}
}

func (w *walker) addSkip(path, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.skipped {
		if s.Path == path { // e.g. /Volumes, seen from both volume walks
			return
		}
	}
	if len(w.skipped) < maxRecorded {
		w.skipped = append(w.skipped, Skip{Path: path, Reason: reason})
	}
}

// startProgress runs the progress callback until the returned stop function
// is called. stop delivers one final update and waits for the goroutine.
func (w *walker) startProgress(start time.Time) (stop func()) {
	if w.opts.Progress == nil {
		return func() {}
	}
	snapshot := func() Progress {
		p := Progress{Files: w.files.Load(), Dirs: w.dirs.Load(), Bytes: w.bytes.Load(), Elapsed: time.Since(start)}
		if c := w.current.Load(); c != nil {
			p.Current = *c
		}
		return p
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(w.opts.ProgressInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				w.opts.Progress(snapshot())
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			wg.Wait()
			w.opts.Progress(snapshot())
		})
	}
}
