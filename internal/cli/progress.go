package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode/utf8"

	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// isTerminal reports whether w is an interactive terminal. Overridable in tests.
var isTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// progressLine draws a single, self-overwriting status line on stderr. It
// does nothing unless stderr is a terminal, so stdout stays clean for pipes
// and logs never fill with carriage returns.
type progressLine struct {
	w       io.Writer
	enabled bool
	width   int
	frame   int
	drawn   bool
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func newProgressLine(w io.Writer) *progressLine {
	width := 80
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 20 {
		width = c
	}
	return &progressLine{w: w, enabled: isTerminal(w) && os.Getenv("TERM") != "dumb", width: width}
}

// update is called from the scanner's progress goroutine; calls are
// serialised by the scanner, so no locking is needed.
func (p *progressLine) update(pr scanner.Progress) {
	if !p.enabled {
		return
	}
	p.frame++
	prefix := fmt.Sprintf("%s %s files · %s · ", spinner[p.frame%len(spinner)], report.Count(pr.Files), report.Bytes(pr.Bytes))
	room := p.width - utf8.RuneCountInString(prefix) - 1
	fmt.Fprintf(p.w, "\r\x1b[K%s%s", prefix, truncateLeft(pr.Current, room))
	p.drawn = true
}

// clear erases the line. Call it after the scan returns.
func (p *progressLine) clear() {
	if p.drawn {
		fmt.Fprint(p.w, "\r\x1b[K")
		p.drawn = false
	}
}

// truncateLeft keeps the end of s (the most specific part of a path).
func truncateLeft(s string, n int) string {
	if n <= 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

// stdinIsTerminal reports whether r is an interactive terminal, for prompts.
// Overridable in tests, which feed answers through a buffer.
var stdinIsTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
