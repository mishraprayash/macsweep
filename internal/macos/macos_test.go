package macos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatfs(t *testing.T) {
	du, err := Statfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if du.Total == 0 || du.Used > du.Total || du.Free > du.Total || du.Available > du.Total {
		t.Errorf("implausible usage: %+v", du)
	}
	if _, err := Statfs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("Statfs on missing path: want error")
	}
}

func TestProbe(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	tests := []struct {
		path string
		want Access
	}{
		{dir, AccessGranted},
		{file, AccessGranted}, // empty file: EOF is not a denial
		{filepath.Join(dir, "missing"), AccessUnknown},
	}
	if os.Geteuid() != 0 {
		tests = append(tests, struct {
			path string
			want Access
		}{locked, AccessDenied})
	}
	for _, tt := range tests {
		if got := probe(tt.path); got != tt.want {
			t.Errorf("probe(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestFullDiskAccessUnknownWhenNoProbesExist(t *testing.T) {
	// Only exercises the home-relative probes; the system TCC.db probe may
	// legitimately decide on a real machine, so only check the result is valid.
	a, p := FullDiskAccess(t.TempDir())
	if a == AccessUnknown && p != "" {
		t.Errorf("unknown access should have no probe path, got %q", p)
	}
	if a != AccessUnknown && p == "" {
		t.Errorf("decided access %v without a probe path", a)
	}
}
