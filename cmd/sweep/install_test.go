package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

// fakeRelease writes a release folder like GitHub's (archive + SHA256SUMS)
// whose "sweep" is a shell script printing a version.
func fakeRelease(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const asset = "sweep-darwin-universal.tar.gz"
	f, err := os.Create(filepath.Join(dir, asset))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho 'sweep version 9.9.9'\n")
	if err := tw.WriteHeader(&tar.Header{Name: "sweep", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	for _, c := range []interface{ Close() error }{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, asset))
	if err != nil {
		t.Fatal(err)
	}
	sums := fmt.Sprintf("%x  %s\n", sha256.Sum256(data), asset)
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runInstall runs install.sh against the fake release with HOME in the
// sandbox. extraPath is prepended to a minimal system PATH.
func runInstall(t *testing.T, s *testutil.Sandbox, release, shell, extraPath string, env ...string) string {
	t.Helper()
	path := "/usr/bin:/bin:/usr/sbin:/sbin"
	if extraPath != "" {
		path = extraPath + ":" + path
	}
	cmd := exec.Command("/bin/sh", filepath.Join("..", "..", "install.sh"))
	cmd.Env = append([]string{
		"HOME=" + s.Home, "SHELL=" + shell, "PATH=" + path, "SWEEP_BASE_URL=file://" + release,
	}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	return string(out)
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallScriptAddsToPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("install.sh only runs on macOS")
	}
	if strings.ContainsRune(t.TempDir(), ' ') {
		t.Skip("file:// URLs with spaces are not supported by the test")
	}
	for _, tt := range []struct {
		shell, rc, line string
	}{
		{"/bin/zsh", ".zshrc", `export PATH="$HOME/.local/bin:$PATH"`},
		{"/bin/bash", ".bash_profile", `export PATH="$HOME/.local/bin:$PATH"`},
		{"/opt/homebrew/bin/fish", ".config/fish/conf.d/sweep.fish", `fish_add_path "%HOME%/.local/bin"`},
	} {
		t.Run(filepath.Base(tt.shell), func(t *testing.T) {
			s := testutil.NewSandbox(t)
			release := filepath.Join(s.Dir, "release")
			fakeRelease(t, release)
			line := strings.ReplaceAll(tt.line, "%HOME%", s.Home)

			out := runInstall(t, s, release, tt.shell, "")
			if !strings.Contains(out, "Installed sweep version 9.9.9") || !strings.Contains(out, "Open a new Terminal window") {
				t.Errorf("output:\n%s", out)
			}
			runInstall(t, s, release, tt.shell, "") // a second install adds nothing
			rc := readFile(t, filepath.Join(s.Home, tt.rc))
			if strings.Count(rc, line) != 1 {
				t.Errorf("%s holds the PATH line %d times, want once:\n%s", tt.rc, strings.Count(rc, line), rc)
			}
			if fi, err := os.Stat(filepath.Join(s.Home, ".local/bin/sweep")); err != nil || fi.Mode()&0o111 == 0 {
				t.Errorf("sweep not installed as an executable: %v", err)
			}
		})
	}
}

func TestInstallScriptLeavesPathAlone(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("install.sh only runs on macOS")
	}
	if strings.ContainsRune(t.TempDir(), ' ') {
		t.Skip("file:// URLs with spaces are not supported by the test")
	}
	s := testutil.NewSandbox(t)
	release := filepath.Join(s.Dir, "release")
	fakeRelease(t, release)
	zshrc := filepath.Join(s.Home, ".zshrc")
	existing := "# my settings\nalias ll='ls -l'\n"
	if err := os.WriteFile(zshrc, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	// Opted out.
	out := runInstall(t, s, release, "/bin/zsh", "", "SWEEP_NO_MODIFY_PATH=1")
	if !strings.Contains(out, "SWEEP_NO_MODIFY_PATH is set") || readFile(t, zshrc) != existing {
		t.Errorf("opt-out changed ~/.zshrc or did not say so:\n%s", out)
	}
	// Already on PATH.
	out = runInstall(t, s, release, "/bin/zsh", filepath.Join(s.Home, ".local/bin"))
	if !strings.Contains(out, "Next: sweep doctor") || readFile(t, zshrc) != existing {
		t.Errorf("install with sweep already on PATH changed ~/.zshrc:\n%s", out)
	}
	// A shell we do not know: instructions only.
	out = runInstall(t, s, release, "/bin/tcsh", "")
	if !strings.Contains(out, "Add it in your shell's startup file") || readFile(t, zshrc) != existing {
		t.Errorf("unknown shell:\n%s", out)
	}
	for _, rc := range []string{".bash_profile", ".config/fish/conf.d/sweep.fish"} {
		if _, err := os.Stat(filepath.Join(s.Home, rc)); err == nil {
			t.Errorf("%s was created", rc)
		}
	}
}
