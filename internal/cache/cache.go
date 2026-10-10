// Package cache persists the last scan so later commands (show,
// clean) can reuse it without rescanning.
package cache

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// formatVersion changes whenever the stored layout changes incompatibly.
const formatVersion = 3

// ErrNoScan is returned by Load when no cached scan exists.
var ErrNoScan = errors.New("no saved scan found; run 'sweep' (or 'sweep scan <path>') first")

// DefaultPath is where the last scan is stored for the given home directory.
func DefaultPath(home string) string {
	return filepath.Join(home, "Library", "Caches", "sweep", "last-scan.gob.gz")
}

// Scan is what is saved: the measurements and their classification.
type Scan struct {
	Result   *scanner.Result
	Findings []classifier.Finding
	// Disk and Container describe the disk at scan time (nil if unavailable).
	Disk      *macos.DiskUsage
	Container *macos.APFSContainer
	// Snapshots are local Time Machine snapshots at scan time.
	Snapshots []macos.Snapshot
	// CleanedItems and CleanedBytes count findings removed by 'sweep clean'
	// since this scan (their files are gone, but tree totals still include them).
	CleanedItems int
	CleanedBytes uint64
}

type envelope struct {
	Version int
	Scan    *Scan // gob ignores json tags, so Result.Tree is included
}

// Save writes s to path atomically (temp file + rename in the same
// directory). It only ever creates or replaces that one file.
func Save(path string, s *Scan) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".last-scan-*.tmp")
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name()) // only the temp file created above
		}
	}()

	zw := gzip.NewWriter(tmp)
	if err := gob.NewEncoder(zw).Encode(envelope{Version: formatVersion, Scan: s}); err != nil {
		return fmt.Errorf("cache: encode: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	return nil
}

// Load reads a scan saved by Save.
func Load(path string) (*Scan, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoScan
	}
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("cache: %s is corrupt (%w); run 'sweep scan' again", path, err)
	}
	var env envelope
	if err := gob.NewDecoder(zr).Decode(&env); err != nil {
		return nil, fmt.Errorf("cache: %s is unreadable (%w); run 'sweep scan' again", path, err)
	}
	if env.Version != formatVersion || env.Scan == nil || env.Scan.Result == nil || env.Scan.Result.Tree == nil {
		return nil, fmt.Errorf("cache: %s was written by an incompatible sweep version; run 'sweep scan' again", path)
	}
	return env.Scan, nil
}
