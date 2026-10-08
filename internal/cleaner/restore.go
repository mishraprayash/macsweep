package cleaner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mishraprayash/macsweep/internal/audit"
)

// RestoreItem is a trashed item that can be moved back.
type RestoreItem struct {
	Session   string `json:"session"`
	Path      string `json:"path"`       // original location
	TrashPath string `json:"trash_path"` // where it is now
	Size      uint64 `json:"size_bytes"`
	RuleID    string `json:"rule_id"`
	// Problem is set when the item cannot be restored as is.
	Problem string `json:"problem,omitempty"`
}

// Sessions reads the audit log and returns the items each session moved to
// the Trash, oldest session first. Records already restored are skipped.
func Sessions(logPath string) (order []string, items map[string][]RestoreItem, err error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	items = map[string][]RestoreItem{}
	restored := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r audit.Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue // a damaged line must not block restoring the rest
		}
		switch {
		case r.Action == "restore" && r.Result == audit.ResultOK:
			restored[r.TrashPath] = true
		case r.Action == string(MethodTrash) && r.Result == audit.ResultOK && r.TrashPath != "":
			if _, ok := items[r.Session]; !ok {
				order = append(order, r.Session)
			}
			items[r.Session] = append(items[r.Session], RestoreItem{
				Session: r.Session, Path: r.Path, TrashPath: r.TrashPath, Size: r.Size, RuleID: r.RuleID,
			})
		}
	}
	for s, list := range items {
		kept := list[:0]
		for _, it := range list {
			if !restored[it.TrashPath] {
				kept = append(kept, it)
			}
		}
		items[s] = kept
	}
	return order, items, sc.Err()
}

// CheckRestore fills in Problem for items that cannot be restored: the log
// entry must point from inside trashDir to an absolute original path that
// is free again, with its parent folder still present.
func CheckRestore(items []RestoreItem, trashDir string) {
	trashDir = filepath.Clean(trashDir)
	for i := range items {
		it := &items[i]
		tp := filepath.Clean(it.TrashPath)
		switch {
		case !strings.HasPrefix(tp, trashDir+"/") || filepath.Dir(tp) != trashDir:
			it.Problem = "log entry does not point into the Trash"
		case !filepath.IsAbs(it.Path) || filepath.Clean(it.Path) != it.Path:
			it.Problem = "log entry has an invalid original path"
		}
		if it.Problem != "" {
			continue
		}
		if _, err := os.Lstat(tp); err != nil {
			it.Problem = "no longer in the Trash (emptied or moved)"
			continue
		}
		if _, err := os.Lstat(it.Path); err == nil {
			it.Problem = "something already exists at the original path"
			continue
		}
		if fi, err := os.Stat(filepath.Dir(it.Path)); err != nil || !fi.IsDir() {
			it.Problem = "the original folder no longer exists"
		}
	}
}

// Restore moves one checked item back. It never overwrites anything.
func Restore(it RestoreItem, log *audit.Log) error {
	if it.Problem != "" {
		return errors.New(it.Problem)
	}
	err := renameExclusive(it.TrashPath, it.Path)
	if errors.Is(err, fs.ErrExist) {
		err = fmt.Errorf("something already exists at %s", it.Path)
	}
	rec := audit.Record{Action: "restore", Path: it.Path, TrashPath: it.TrashPath, Size: it.Size, RuleID: it.RuleID, Result: audit.ResultOK}
	if err != nil {
		rec.Result, rec.Error = audit.ResultFailed, err.Error()
	}
	if lerr := log.Append(rec); lerr != nil && err == nil {
		err = lerr
	}
	return err
}
