package cleaner

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
	"syscall"
	"time"

	"github.com/mishraprayash/macsweep/internal/audit"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
)

// Runner runs a native cleanup command.
type Runner interface {
	Run(ctx context.Context, cmd []string, out io.Writer) error
}

// ExecRunner runs commands with os/exec, streaming their output.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, cmd []string, out io.Writer) error {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...) //nolint:gosec // only allow-listed programs reach here
	c.Stdout, c.Stderr = out, out
	return c.Run()
}

// Executor carries out a plan.
type Executor struct {
	Guard    *safety.Guard
	Rules    *rules.Set
	TrashDir string
	Audit    *audit.Log
	Runner   Runner
	// Out receives one line per action, and native command output.
	Out io.Writer
	// OpenFiles lists the files running processes have open, read once just
	// before cleaning starts. If it fails, nothing is moved or deleted. Nil
	// skips the check (tests only).
	OpenFiles func() (*macos.OpenFiles, error)

	open *macos.OpenFiles
}

// Outcome is what happened to one path.
type Outcome struct {
	Path      string `json:"path"`
	Method    Method `json:"method"`
	RuleID    string `json:"rule_id"`
	Size      uint64 `json:"size_bytes"`
	Result    string `json:"result"`
	Reason    string `json:"reason,omitempty"`
	TrashPath string `json:"trash_path,omitempty"`
}

// Summary totals an execution.
type Summary struct {
	Outcomes []Outcome `json:"outcomes"`
	// Freed counts bytes removed or moved to the Trash (scan-time sizes).
	// Native commands are not included: their effect is reported by the tool.
	Freed       uint64 `json:"freed_bytes"`
	Trashed     int    `json:"trashed"`
	Deleted     int    `json:"deleted"`
	NativeRuns  int    `json:"native_commands"`
	Skipped     int    `json:"skipped"`
	Failed      int    `json:"failed"`
	Interrupted bool   `json:"interrupted"`
	AuditLog    string `json:"audit_log"`
	// Cleaned lists finding paths fully handled, so the saved scan can drop them.
	Cleaned []string `json:"-"`
}

// Execute runs the plan: files first, then native commands. It stops early
// (between items) if ctx is cancelled.
func (e *Executor) Execute(ctx context.Context, p *Plan) *Summary {
	s := &Summary{AuditLog: e.Audit.Path()}
	if err := e.ensureTrash(p); err != nil {
		for _, it := range p.Items {
			if it.Method == MethodTrash {
				e.record(s, it, it.Path, it.Size, audit.ResultFailed, err.Error(), "")
			}
		}
		return s
	}
	if e.OpenFiles != nil {
		open, err := e.OpenFiles()
		if err != nil {
			for _, it := range p.Items {
				if it.Method != MethodNative {
					e.record(s, it, it.Path, it.Size, audit.ResultSkipped, "could not check which files are in use: "+err.Error(), "")
				}
			}
			return s
		}
		e.open = open
	}
	for _, it := range p.Items {
		if it.Method == MethodNative {
			continue
		}
		if ctx.Err() != nil {
			s.Interrupted = true
			return s
		}
		e.cleanItem(it, p.ScanRoot, s)
	}
	for _, g := range p.NativeGroups() {
		if ctx.Err() != nil {
			s.Interrupted = true
			return s
		}
		e.runNative(ctx, g, s)
	}
	return s
}

func (e *Executor) cleanItem(it Item, scanRoot string, s *Summary) {
	target := safety.Target{
		Path: it.Path, RuleID: it.RuleID, Tier: it.Tier, ScanRoot: scanRoot, Dev: it.Dev, Ino: it.Ino,
	}
	if it.Contents {
		if err := e.revalidateContainer(target); err != nil {
			e.record(s, it, it.Path, it.Size, audit.ResultSkipped, reasonOf(err), "")
			return
		}
		entries, err := os.ReadDir(it.Path)
		if err != nil {
			e.record(s, it, it.Path, it.Size, audit.ResultFailed, err.Error(), "")
			return
		}
		allOK := true
		for _, ent := range entries {
			child := filepath.Join(it.Path, ent.Name())
			size, _, _ := contentStats(child)
			if err := e.Guard.CheckDeletable(child, it.Tier); err != nil {
				e.record(s, it, child, size, audit.ResultSkipped, reasonOf(err), "")
				allOK = false
				continue
			}
			if !e.removeOne(it, child, size, s) {
				allOK = false
			}
		}
		if allOK {
			s.Cleaned = append(s.Cleaned, it.Path)
		}
		return
	}

	if err := e.Guard.Revalidate(target, e.matcher()); err != nil {
		e.record(s, it, it.Path, it.Size, audit.ResultSkipped, reasonOf(err), "")
		return
	}
	if e.removeOne(it, it.Path, it.Size, s) {
		s.Cleaned = append(s.Cleaned, it.Path)
	}
}

// removeOne trashes or deletes a single path after the in-use and content
// checks.
func (e *Executor) removeOne(it Item, path string, size uint64, s *Summary) bool {
	if cmd, open := e.open.Under(path); open {
		e.record(s, it, path, size, audit.ResultSkipped, "in use by "+cmd, "")
		return false
	}
	if e.needsContentCheck(it, path) {
		if hit, err := findSensitive(path); err != nil {
			e.record(s, it, path, size, audit.ResultSkipped, "could not inspect contents: "+err.Error(), "")
			return false
		} else if hit != "" {
			e.record(s, it, path, size, audit.ResultSkipped, fmt.Sprintf("contains %s; delete it yourself if you are sure", hit), "")
			return false
		}
	}
	switch it.Method {
	case MethodTrash:
		dest, err := moveToTrash(path, e.TrashDir)
		if err != nil {
			reason := err.Error()
			switch {
			case errors.Is(err, errCrossDevice):
				reason = "on a different volume than the Trash; rerun with --permanent to delete it"
			case errors.Is(err, fs.ErrPermission):
				reason = "permission denied moving it to the Trash (writing ~/.Trash needs Full Disk Access for your terminal; see 'sweep doctor')"
			}
			e.record(s, it, path, size, audit.ResultFailed, reason, "")
			return false
		}
		e.record(s, it, path, size, audit.ResultOK, "", dest)
	case MethodPermanent:
		if err := os.RemoveAll(path); err != nil {
			e.record(s, it, path, size, audit.ResultFailed, err.Error(), "")
			return false
		}
		e.record(s, it, path, size, audit.ResultOK, "", "")
	default:
		e.record(s, it, path, size, audit.ResultFailed, "unknown method "+string(it.Method), "")
		return false
	}
	return true
}

// needsContentCheck: directories are checked for .git/.env before removal,
// except node_modules (packages ship their own .git), built-in caches at
// fixed paths or fixed ~/Library locations (tool-managed; e.g. Cargo's
// registry index is a git checkout) and what a tool-managed detector found
// (old versions). User rules, project artifacts, other detectors' findings
// (e.g. an uninstalled app's data) and wider globs (e.g. ~/.cache/*, where any
// tool may keep anything) are always checked.
func (e *Executor) needsContentCheck(it Item, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	if filepath.Base(path) == "node_modules" {
		return false
	}
	r, ok := e.Rules.ByID(it.RuleID)
	if !ok || r.User {
		return true
	}
	if r.Synthetic {
		d, _ := rules.DetectorFor(r.ID)
		return !d.ToolManaged
	}
	if len(r.Match.Path) > 0 {
		return false
	}
	if len(r.Match.Glob) == 0 {
		return true
	}
	for _, g := range r.Match.Glob {
		if !strings.HasPrefix(g, "~/Library/") && !strings.HasPrefix(g, "/Library/") {
			return true
		}
	}
	return false
}

func (e *Executor) runNative(ctx context.Context, g NativeGroup, s *Summary) {
	cmd := g.Command
	if len(cmd) == 0 || !rules.AllowedNative(cmd[0]) {
		for _, it := range g.Items {
			e.recordNative(s, it, cmd, audit.ResultSkipped, "command not allowed")
		}
		return
	}
	fmt.Fprintf(e.Out, "$ %s\n", strings.Join(cmd, " "))
	err := e.Runner.Run(ctx, cmd, e.Out)
	s.NativeRuns++
	for _, it := range g.Items {
		if err != nil {
			e.recordNative(s, it, cmd, audit.ResultFailed, nativeHint(cmd, err))
			continue
		}
		e.recordNative(s, it, cmd, audit.ResultOK, "")
		s.Cleaned = append(s.Cleaned, it.Path)
	}
}

// nativeHint explains a failed native command and how to run it by hand.
// sweep never escalates privileges itself.
func nativeHint(cmd []string, err error) string {
	line := strings.Join(cmd, " ")
	hint := ""
	switch cmd[0] {
	case "docker":
		hint = " (is Docker Desktop running?)"
	case "tmutil":
		hint = "; if it needs admin rights, run it yourself: sudo " + line
	case "xcrun":
		hint = " (needs Xcode or the Command Line Tools)"
	}
	return fmt.Sprintf("`%s` failed: %v%s", line, err, hint)
}

func (e *Executor) recordNative(s *Summary, it Item, cmd []string, result, reason string) {
	o := Outcome{Path: it.Path, Method: MethodNative, RuleID: it.RuleID, Size: it.Size, Result: result, Reason: reason}
	s.Outcomes = append(s.Outcomes, o)
	switch result {
	case audit.ResultFailed:
		s.Failed++
	case audit.ResultSkipped:
		s.Skipped++
	}
	_ = e.Audit.Append(audit.Record{
		Action: string(MethodNative), Path: it.Path, Size: it.Size, RuleID: it.RuleID, Tier: it.Tier.String(),
		Result: result, Error: reason, Command: cmd,
	})
}

func (e *Executor) record(s *Summary, it Item, path string, size uint64, result, reason, trashPath string) {
	o := Outcome{Path: path, Method: it.Method, RuleID: it.RuleID, Size: size, Result: result, Reason: reason, TrashPath: trashPath}
	s.Outcomes = append(s.Outcomes, o)
	switch result {
	case audit.ResultOK:
		s.Freed += size
		if it.Method == MethodTrash {
			s.Trashed++
		} else {
			s.Deleted++
		}
	case audit.ResultSkipped:
		s.Skipped++
	case audit.ResultFailed:
		s.Failed++
	}
	rec := audit.Record{
		Action: string(it.Method), Path: path, Size: size, RuleID: it.RuleID, Tier: it.Tier.String(),
		Result: result, TrashPath: trashPath,
	}
	if result == audit.ResultFailed {
		rec.Error = reason
	} else {
		rec.Reason = reason
	}
	_ = e.Audit.Append(rec)
	if e.Out != nil {
		mark := map[string]string{audit.ResultOK: "✓", audit.ResultSkipped: "-", audit.ResultFailed: "✗"}[result]
		verb := map[Method]string{MethodTrash: "moved to Trash", MethodPermanent: "deleted"}[it.Method]
		if result != audit.ResultOK {
			verb = result + ": " + reason
		}
		fmt.Fprintf(e.Out, "%s %s  %s\n", mark, path, verb)
	}
}

// ensureTrash creates the Trash directory if a Trash item is planned and it
// does not exist yet (it always exists on a normal Mac account).
func (e *Executor) ensureTrash(p *Plan) error {
	for _, it := range p.Items {
		if it.Method != MethodTrash {
			continue
		}
		fi, err := os.Lstat(e.TrashDir)
		switch {
		case err == nil && fi.IsDir():
			return nil
		case err == nil:
			return fmt.Errorf("the Trash (%s) is not a directory", e.TrashDir)
		case errors.Is(err, fs.ErrNotExist):
			return os.Mkdir(e.TrashDir, 0o700)
		default:
			return fmt.Errorf("cannot use the Trash: %w", err)
		}
	}
	return nil
}

// matcher re-runs the rules against a live path, for Revalidate. A folder
// matched on size or age (min_size, min_age_days) is measured again, so
// something written into it since the scan keeps it; if it cannot be read
// completely, it does not match.
func (e *Executor) matcher() safety.Matcher {
	return func(path string, info fs.FileInfo) (string, bool) {
		cand := rules.Candidate{Path: path, IsDir: info.IsDir(), MTime: info.ModTime()}
		if !info.IsDir() {
			cand.Size = allocated(info)
		}
		res, ok := e.Rules.Match(cand)
		if !ok {
			return "", false
		}
		if res.Deferred {
			size, newest, err := contentStats(path)
			if err != nil || !e.Rules.SizeAgeOK(res.Rule, size, newest) {
				return "", false
			}
		}
		return res.Rule.ID, true
	}
}

// revalidateContainer checks a directory that will be emptied: it must still
// be the same, non-symlinked directory, matched by the same rule, and not
// protected. (It may itself be too shallow to delete, e.g. ~/.Trash.)
func (e *Executor) revalidateContainer(t safety.Target) error {
	fi, err := os.Lstat(t.Path)
	if err != nil {
		return &safety.Violation{Kind: safety.ErrChanged, Path: t.Path, Reason: "no longer exists"}
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return &safety.Violation{Kind: safety.ErrChanged, Path: t.Path, Reason: "is no longer a directory"}
	}
	if t.Ino != 0 {
		if dev, ino, ok := safety.FileID(fi); !ok || dev != t.Dev || ino != t.Ino {
			return &safety.Violation{Kind: safety.ErrChanged, Path: t.Path, Reason: "was replaced"}
		}
	}
	if id, ok := e.matcher()(t.Path, fi); !ok || id != t.RuleID {
		return &safety.Violation{Kind: safety.ErrChanged, Path: t.Path, Reason: "is no longer matched by rule " + t.RuleID}
	}
	if reason, bad := e.Guard.Protected(t.Path); bad {
		return &safety.Violation{Kind: safety.ErrProtected, Path: t.Path, Reason: reason}
	}
	return nil
}

// findSensitive walks dir (without following symlinks) and returns the
// first .git or .env* entry found, skipping node_modules subtrees. Unreadable
// subdirectories are an error: if we cannot look, we do not delete.
func findSensitive(dir string) (string, error) {
	var hit string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		name := d.Name()
		if name == ".git" || strings.HasPrefix(name, ".env") {
			hit, _ = filepath.Rel(dir, p)
			return fs.SkipAll
		}
		if d.IsDir() && name == "node_modules" {
			return fs.SkipDir
		}
		return nil
	})
	return hit, err
}

// contentStats returns the allocated bytes under p and the newest file
// modification time in it (not following symlinks), measured like the
// scanner's Node.Size and Node.Newest so a re-check agrees with the scan. It
// counts what it can read and reports the first error, if any.
func contentStats(p string) (size uint64, newest time.Time, err error) {
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr == nil {
			var fi fs.FileInfo
			if fi, walkErr = d.Info(); walkErr == nil {
				size += allocated(fi)
				if !d.IsDir() && fi.ModTime().After(newest) {
					newest = fi.ModTime()
				}
				return nil
			}
		}
		if err == nil {
			err = walkErr
		}
		return nil // keep counting what can be read
	})
	return size, newest, err
}

func allocated(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(max(st.Blocks, 0)) * 512
	}
	return uint64(max(fi.Size(), 0))
}
