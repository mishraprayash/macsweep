package cleaner

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

var errCrossDevice = errors.New("item is on a different volume than the Trash")

// maxTrashNames bounds the search for a free name in the Trash.
const maxTrashNames = 10000

// moveToTrash renames src into trashDir, picking "name 2", "name 3", ...
// (as Finder does) when the name is taken. The rename never overwrites an
// existing item: on macOS it uses renamex_np(RENAME_EXCL).
func moveToTrash(src, trashDir string) (string, error) {
	base := filepath.Base(src)
	ext := filepath.Ext(base)
	if ext == base { // dotfiles like .next have no extension
		ext = ""
	}
	stem := strings.TrimSuffix(base, ext)
	for i := 1; i <= maxTrashNames; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s %d%s", stem, i, ext)
		}
		dst := filepath.Join(trashDir, name)
		err := renameExclusive(src, dst)
		switch {
		case err == nil:
			return dst, nil
		case errors.Is(err, fs.ErrExist), errors.Is(err, syscall.ENOTEMPTY):
			continue
		case errors.Is(err, syscall.EXDEV):
			return "", errCrossDevice
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("no free name for %s in the Trash", base)
}
