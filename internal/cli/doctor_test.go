package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/macos"
)

func fakeDoctorDeps(access macos.Access) doctorDeps {
	return doctorDeps{
		home:    func() (string, error) { return "/Users/sweep-test-user", nil },
		version: func(context.Context) (string, error) { return "15.4.1", nil },
		fda: func(string) (macos.Access, string) {
			return access, "/Library/Application Support/com.apple.TCC/TCC.db"
		},
		volume: func() string { return macos.DataVolume },
		statfs: func(p string) (macos.DiskUsage, error) {
			return macos.DiskUsage{Path: p, Total: 494_400_000_000, Used: 401_200_000_000, Free: 93_200_000_000, Available: 90_000_000_000}, nil
		},
		euid:     func() int { return 501 },
		terminal: func() string { return "iTerm" },
	}
}

func runCmd(t *testing.T, deps doctorDeps, args ...string) (stdout string, code int) {
	t.Helper()
	color.NoColor = true
	var out, errb bytes.Buffer
	cmd := newRootCmd("test", deps)
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	code = run(context.Background(), cmd, &errb)
	return out.String(), code
}

func TestDoctorText(t *testing.T) {
	tests := []struct {
		access     macos.Access
		wantSubstr []string
		notSubstr  []string
	}{
		{macos.AccessGranted, []string{"✓ granted", "15.4.1", "494.4 GB total", "base-10"}, []string{"To grant it"}},
		{macos.AccessDenied, []string{"✗ not granted", "To grant it", "Turn on iTerm"}, nil},
		{macos.AccessUnknown, []string{"could not determine", "To grant it"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.access.String(), func(t *testing.T) {
			out, code := runCmd(t, fakeDoctorDeps(tt.access), "doctor")
			if code != 0 {
				t.Fatalf("exit code %d", code)
			}
			for _, s := range tt.wantSubstr {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q:\n%s", s, out)
				}
			}
			for _, s := range tt.notSubstr {
				if strings.Contains(out, s) {
					t.Errorf("output unexpectedly contains %q:\n%s", s, out)
				}
			}
		})
	}
}

func TestDoctorJSON(t *testing.T) {
	out, code := runCmd(t, fakeDoctorDeps(macos.AccessDenied), "doctor", "--json")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got["full_disk_access"] != "denied" || got["macos_version"] != "15.4.1" || got["running_as_root"] != false {
		t.Errorf("unexpected JSON: %s", out)
	}
	disk, ok := got["disk"].(map[string]any)
	if !ok || disk["total_bytes"] != float64(494_400_000_000) {
		t.Errorf("unexpected disk: %v", got["disk"])
	}
}

func TestDoctorDegradesGracefully(t *testing.T) {
	deps := fakeDoctorDeps(macos.AccessGranted)
	deps.version = func(context.Context) (string, error) { return "", errors.New("boom") }
	deps.statfs = func(string) (macos.DiskUsage, error) { return macos.DiskUsage{}, errors.New("nope") }
	out, code := runCmd(t, deps, "doctor")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for _, s := range []string{"could not read macOS version", "could not read disk totals", "unknown"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q:\n%s", s, out)
		}
	}
}

func TestRunExitCodes(t *testing.T) {
	_, code := runCmd(t, fakeDoctorDeps(macos.AccessGranted), "no-such-command")
	if code != 1 {
		t.Errorf("unknown command: exit %d, want 1", code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := fakeDoctorDeps(macos.AccessGranted)
	deps.version = func(ctx context.Context) (string, error) { return "", ctx.Err() }
	cmd := newRootCmd("test", deps)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"doctor"})
	var errb bytes.Buffer
	if code := run(ctx, cmd, &errb); code != 130 {
		t.Errorf("cancelled context: exit %d, want 130 (stderr %q)", code, errb.String())
	}
}
