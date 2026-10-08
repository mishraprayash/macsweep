// Package macos wraps the macOS facilities sweep relies on: statfs disk
// totals, OS version, and Full Disk Access detection.
package macos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// DataVolume is the APFS data volume, firmlinked into / on macOS 10.15+.
const DataVolume = "/System/Volumes/Data"

// DiskUsage holds filesystem totals in bytes. On APFS, Total and Free describe
// the whole container shared by all of its volumes.
type DiskUsage struct {
	Path      string `json:"path"`
	Total     uint64 `json:"total_bytes"`
	Used      uint64 `json:"used_bytes"`
	Free      uint64 `json:"free_bytes"`
	Available uint64 `json:"available_bytes"`
}

// Statfs returns disk totals for the filesystem containing path.
func Statfs(path string) (DiskUsage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return DiskUsage{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	bs := uint64(st.Bsize)
	total := st.Blocks * bs
	free := st.Bfree * bs
	return DiskUsage{
		Path:      path,
		Total:     total,
		Used:      total - free,
		Free:      free,
		Available: st.Bavail * bs,
	}, nil
}

// SystemVolume returns the path whose statfs best represents the user's
// disk: the data volume when it exists, otherwise /.
func SystemVolume() string {
	if fi, err := os.Stat(DataVolume); err == nil && fi.IsDir() {
		return DataVolume
	}
	return "/"
}

// ProductVersion returns the macOS version, e.g. "15.4.1".
func ProductVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "sw_vers", "-productVersion").Output()
	if err != nil {
		return "", fmt.Errorf("sw_vers: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Access is the result of a Full Disk Access probe.
type Access int

const (
	AccessUnknown Access = iota
	AccessGranted
	AccessDenied
)

func (a Access) String() string {
	switch a {
	case AccessGranted:
		return "granted"
	case AccessDenied:
		return "denied"
	default:
		return "unknown"
	}
}

func (a Access) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// fdaProbes are TCC-protected locations that are only readable with Full
// Disk Access. The first one that exists decides.
func fdaProbes(home string) []string {
	return []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		filepath.Join(home, "Library", "Safari"),
		filepath.Join(home, "Library", "Mail"),
		filepath.Join(home, "Library", "Messages"),
	}
}

// FullDiskAccess probes whether this process (and so the terminal that
// launched it) has Full Disk Access. It only opens and reads; it never
// writes. It also returns the probe path that decided.
func FullDiskAccess(home string) (Access, string) {
	for _, p := range fdaProbes(home) {
		switch probe(p) {
		case AccessGranted:
			return AccessGranted, p
		case AccessDenied:
			return AccessDenied, p
		}
	}
	return AccessUnknown, ""
}

func probe(p string) Access {
	f, err := os.Open(p)
	if err != nil {
		return accessFromErr(err)
	}
	defer func() { _ = f.Close() }() // read-only; close errors are irrelevant
	fi, err := f.Stat()
	if err != nil {
		return accessFromErr(err)
	}
	if fi.IsDir() {
		_, err = f.Readdirnames(1)
	} else {
		_, err = f.Read(make([]byte, 1))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return accessFromErr(err)
	}
	return AccessGranted
}

func accessFromErr(err error) Access {
	if errors.Is(err, fs.ErrPermission) {
		return AccessDenied
	}
	return AccessUnknown
}

// Terminal returns a best-effort name for the terminal app, used in
// Full Disk Access instructions.
func Terminal() string {
	switch tp := os.Getenv("TERM_PROGRAM"); tp {
	case "Apple_Terminal":
		return "Terminal"
	case "iTerm.app":
		return "iTerm"
	case "vscode":
		return "Visual Studio Code"
	case "WarpTerminal":
		return "Warp"
	case "":
		return "your terminal app"
	default:
		return tp
	}
}
