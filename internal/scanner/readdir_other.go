//go:build !darwin

package scanner

// readDirFast is readdir + lstat off macOS.
func readDirFast(path string) ([]dirent, error) { return readDirPortable(path) }

// listDirFast lists path by name; descriptors are not used off macOS.
func listDirFast(_ int, _, path string) (int, []dirent, error) {
	ents, err := readDirPortable(path)
	return -1, ents, err
}

func closeDir(int) {}
