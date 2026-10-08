//go:build !darwin

package scanner

import (
	"syscall"
	"time"
)

// sweep targets macOS; these fallbacks only keep the package compiling
// elsewhere (e.g. for linting on Linux CI).

func atime(*syscall.Stat_t) time.Time { return time.Time{} }

func networkFS(string) bool { return true }
