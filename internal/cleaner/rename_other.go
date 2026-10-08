//go:build !darwin

package cleaner

import (
	"io/fs"
	"os"
)

// renameExclusive renames src to dst unless dst exists. Off macOS this has a
// small race between the check and the rename; sweep targets macOS.
func renameExclusive(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fs.ErrExist
	}
	return os.Rename(src, dst)
}
