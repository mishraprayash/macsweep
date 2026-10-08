//go:build darwin

package scanner

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func atime(st *syscall.Stat_t) time.Time {
	return time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec)
}

// networkFS reports whether path is on a network filesystem. Errors are
// treated as "network" so that unknown mounts are skipped.
func networkFS(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return true
	}
	switch unix.ByteSliceToString(st.Fstypename[:]) {
	case "nfs", "smbfs", "afpfs", "webdav", "ftp", "cifs", "autofs", "macfuse", "osxfuse":
		return true
	}
	return false
}
