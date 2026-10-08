package scanner

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// dirent is one directory entry with the attributes the scanner needs.
// It is filled either by getattrlistbulk(2) (macOS, one syscall per batch of
// entries) or by readdir + lstat (everywhere else, and as a fallback).
type dirent struct {
	name   string
	isDir  bool
	isLink bool
	// mountPoint is set when the entry is the root of another mounted
	// filesystem; dev then describes the mounted filesystem.
	mountPoint bool
	dev, ino   uint64
	nlink      uint32
	alloc      uint64 // allocated bytes
	size       uint64 // logical length
	mtime      time.Time
	atime      time.Time
	err        error // per-entry error (e.g. EPERM); other fields invalid
}

// readDirFunc lists a directory. The scanner uses readDirFast where
// available; tests compare it against readDirPortable.
type readDirFunc func(path string) ([]dirent, error)

// readDirPortable lists path with readdir and one lstat per entry.
func readDirPortable(path string) ([]dirent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, rerr := f.ReadDir(-1)
	_ = f.Close()
	out := make([]dirent, 0, len(entries))
	for _, e := range entries {
		d := dirent{name: e.Name()}
		fi, err := e.Info() // lstat: symlinks are never followed
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // vanished
			}
			d.err = err
			out = append(out, d)
			continue
		}
		fillFromStat(&d, fi)
		out = append(out, d)
	}
	return out, rerr
}

func fillFromStat(d *dirent, fi fs.FileInfo) {
	d.isDir = fi.IsDir()
	d.isLink = fi.Mode()&fs.ModeSymlink != 0
	if !d.isDir { // a directory's st_size is filesystem bookkeeping, not data
		d.size = uint64(max(fi.Size(), 0))
	}
	d.mtime = fi.ModTime()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		d.dev = devOf(st)
		d.ino = st.Ino
		d.nlink = uint32(st.Nlink)
		d.alloc = allocated(st)
		d.atime = atime(st)
	}
}

// lstatDirent describes a single path (used for scan roots and mount points).
func lstatDirent(path string) (dirent, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return dirent{}, err
	}
	var d dirent
	fillFromStat(&d, fi)
	d.name = fi.Name()
	return d, nil
}
