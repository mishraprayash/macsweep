package safety

import (
	"errors"
	"fmt"
)

// Sentinel kinds for Violation. Use errors.Is to test for them.
var (
	ErrUnsafePath = errors.New("unsafe path")
	ErrProtected  = errors.New("protected path")
	ErrTier       = errors.New("tier not deletable")
	ErrChanged    = errors.New("path changed since scan")
)

// Violation explains why the guard refused a path. Reason is meant for the
// user and the audit log.
type Violation struct {
	Kind   error
	Path   string
	Reason string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%v: %q: %s", v.Kind, v.Path, v.Reason)
}

func (v *Violation) Unwrap() error { return v.Kind }

func violation(kind error, path, format string, args ...any) error {
	return &Violation{Kind: kind, Path: path, Reason: fmt.Sprintf(format, args...)}
}
