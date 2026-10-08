//go:build darwin

package cleaner

import "golang.org/x/sys/unix"

// renameExclusive renames src to dst, failing with EEXIST if dst exists.
func renameExclusive(src, dst string) error {
	return unix.RenamexNp(src, dst, unix.RENAME_EXCL)
}
