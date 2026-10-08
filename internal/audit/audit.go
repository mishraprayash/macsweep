// Package audit appends a record of every cleanup action to a JSONL file
// (~/Library/Logs/sweep/history.jsonl). The log is append-only: sweep never
// rewrites or truncates it, and the safety layer protects its directory.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Result values for Record.Result.
const (
	ResultOK      = "ok"
	ResultSkipped = "skipped"
	ResultFailed  = "failed"
)

// Record is one line of the audit log.
type Record struct {
	Time    time.Time `json:"time"`
	Session string    `json:"session"`
	// Action is "trash", "permanent", or "native".
	Action string `json:"action"`
	Path   string `json:"path"`
	Size   uint64 `json:"size_bytes"`
	RuleID string `json:"rule_id"`
	Tier   string `json:"tier"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
	Reason string `json:"reason,omitempty"`
	// TrashPath is where a trashed item now lives, for manual restore.
	TrashPath string   `json:"trash_path,omitempty"`
	Command   []string `json:"command,omitempty"`
}

// DefaultPath is the audit log for a home directory.
func DefaultPath(home string) string {
	return filepath.Join(home, "Library", "Logs", "sweep", "history.jsonl")
}

// Log appends records for one cleanup session.
type Log struct {
	mu      sync.Mutex
	f       *os.File
	session string
	now     func() time.Time
}

// Open opens (creating if needed) the log at path for appending.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &Log{f: f, session: newSession(now()), now: now}, nil
}

func newSession(t time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// Session identifies this run in the log.
func (l *Log) Session() string { return l.session }

// Path is the log file's path.
func (l *Log) Path() string { return l.f.Name() }

// Append writes one record and syncs it to disk, so the record survives even
// if sweep is interrupted right after the action.
func (l *Log) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Time = l.now()
	r.Session = l.session
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return l.f.Sync()
}

// Close closes the log.
func (l *Log) Close() error { return l.f.Close() }
