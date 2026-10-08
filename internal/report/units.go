// Package report renders scan results as tables, summaries, and JSON.
package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UnitsNote explains the size convention, for display alongside reports.
const UnitsNote = "Sizes are base-10 (1 GB = 1,000,000,000 bytes), matching Finder."

// Bytes formats n in base-10 units to match Finder, e.g. 48.2 GB.
func Bytes(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"kB", "MB", "GB", "TB", "PB", "EB"}
	v := float64(n) / unit
	i := 0
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	// Avoid showing "1000.0 MB" when rounding crosses a unit boundary.
	if v >= 999.95 && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// Count formats n with thousands separators, e.g. 1,240.
func Count(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// Age formats how long ago t was, coarsely: "just now", "5 minutes ago",
// "3 days ago".
func Age(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute") + " ago"
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour") + " ago"
	default:
		return plural(int(d/(24*time.Hour)), "day") + " ago"
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
