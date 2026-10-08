package report

import (
	"testing"
	"time"
)

func TestCount(t *testing.T) {
	for in, want := range map[uint64]string{0: "0", 999: "999", 1000: "1,000", 1240: "1,240", 12345: "12,345", 1234567: "1,234,567"} {
		if got := Count(in); got != want {
			t.Errorf("Count(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestAge(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		time.Minute:      "1 minute ago",
		5 * time.Minute:  "5 minutes ago",
		3 * time.Hour:    "3 hours ago",
		72 * time.Hour:   "3 days ago",
	} {
		if got := Age(now.Add(-d), now); got != want {
			t.Errorf("Age(-%v) = %q, want %q", d, got, want)
		}
	}
}

func TestBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1000, "1.0 kB"},
		{1500, "1.5 kB"},
		{999_949, "999.9 kB"},
		{999_999, "1.0 MB"},
		{48_200_000_000, "48.2 GB"},
		{1_000_000_000_000, "1.0 TB"},
		{^uint64(0), "18.4 EB"},
	}
	for _, tt := range tests {
		if got := Bytes(tt.in); got != tt.want {
			t.Errorf("Bytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
