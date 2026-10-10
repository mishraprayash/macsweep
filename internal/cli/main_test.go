package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/mishraprayash/macsweep/internal/cleaner"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/rules"
)

// TestMain is a backstop: even a test that forgets to use testutil.NewSandbox
// runs with $HOME pointing at a throwaway directory, so nothing in the real
// ~/Library/Caches/sweep (or any other home path) can be written. It also
// replaces the disk probe so tests never run diskutil.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "sweep-cli-home-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Setenv("HOME", home)
	_ = os.Setenv("NO_COLOR", "1")
	systemProbe = fakeSystemProbe
	runningApps = func(context.Context) map[string]bool { return nil }
	openFiles = func(context.Context) (*macos.OpenFiles, error) { return nil, nil }
	installedApps = func(string) rules.AppLookup { return nil }
	// Never run real cleanup tools, and do not depend on what is installed.
	newRunner = func() cleaner.Runner { return testRunner }
	lookPath = func(cmd string) (string, error) { return "/fake/bin/" + cmd, nil }
	code := m.Run()
	_ = os.RemoveAll(home) // the directory created just above
	os.Exit(code)
}

// testRunner records native commands instead of running them.
var testRunner = &recordingRunner{}

type recordingRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingRunner) Run(_ context.Context, cmd []string, _ io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cmd)
	return nil
}

func (r *recordingRunner) take() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.calls
	r.calls = nil
	return c
}

// fakeSystemProbe describes a 500 GB disk with the usual APFS volumes and
// two local snapshots.
func fakeSystemProbe(context.Context) systemInfo {
	return systemInfo{
		disk: &macos.DiskUsage{Path: macos.DataVolume, Total: 500e9, Used: 400e9, Free: 100e9, Available: 100e9},
		snapshots: []macos.Snapshot{
			{Name: "com.apple.TimeMachine.2026-10-01-010101.local"}, {Name: "com.apple.TimeMachine.2026-10-02-010101.local"},
		},
		container: &macos.APFSContainer{Reference: "disk3", Capacity: 500e9, Free: 100e9, Volumes: []macos.APFSVolume{
			{Device: "disk3s1", Name: "Macintosh HD", Roles: []string{"System"}, Used: 12e9},
			{Device: "disk3s2", Name: "Preboot", Roles: []string{"Preboot"}, Used: 7e9},
			{Device: "disk3s3", Name: "Recovery", Roles: []string{"Recovery"}, Used: 1e9},
			{Device: "disk3s5", Name: "Data", Roles: []string{"Data"}, Used: 378e9},
			{Device: "disk3s6", Name: "VM", Roles: []string{"VM"}, Used: 2e9},
		}},
	}
}
