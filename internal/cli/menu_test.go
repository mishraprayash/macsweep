package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

// atTerminal makes stdout count as a terminal too, as for a person running
// sweep (sweepIn does the same for stdin).
func atTerminal(t *testing.T) {
	t.Helper()
	orig := isTerminal
	isTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { isTerminal = orig })
}

func TestMenuCleansAndUndoes(t *testing.T) {
	s := testutil.NewSandbox(t)
	testutil.Build(t, s.Home, testutil.Tree{
		"code/web/package.json":        testutil.File{Size: 10},
		"code/web/node_modules/r/i.js": testutil.File{Size: 2_000_000},
	})
	atTerminal(t)
	nm := filepath.Join(s.Home, "code/web/node_modules")

	// 3: clean up (y), Enter; 6: undo (y), Enter; q.
	out, stderr, code := sweepIn(t, "3\ny\n\n6\ny\n\nq\n", true)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, stderr)
	}
	for _, want := range []string{
		"Looking through your home folder", "Safe to clean now:", "Choose a number",
		"(same as typing: sweep clean --execute)", "moved to Trash",
		"(same as typing: sweep restore --execute)", "restored",
	} {
		if !strings.Contains(out+stderr, want) {
			t.Errorf("menu output missing %q:\n%s\n%s", want, out, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(nm, "r/i.js")); err != nil {
		t.Errorf("node_modules not back after undo: %v", err)
	}
}

func TestMenuInput(t *testing.T) {
	testutil.NewSandbox(t)
	atTerminal(t)
	// A choice that is not on the menu, then the input ends (Ctrl-D).
	out, stderr, code := sweepIn(t, "9\n", true)
	if code != 0 || !strings.Contains(out, `"9" is not on the menu`) {
		t.Errorf("exit %d\n%s\n%s", code, out, stderr)
	}
}

func TestMenuOnlyForPeople(t *testing.T) {
	testutil.NewSandbox(t)
	atTerminal(t)
	for _, args := range [][]string{nil, {"--json"}} {
		terminal := args != nil // --json at a terminal; nothing at all without one
		out, _, code := sweepIn(t, "q\n", terminal, args...)
		if code != 0 || strings.Contains(out, "Choose a number") {
			t.Errorf("sweep %v (terminal %v) showed the menu:\n%s", args, terminal, out)
		}
	}
}

// TestMenuChoicesAreCommands: every menu choice must be a command sweep
// accepts, since the menu only runs commands.
func TestMenuChoicesAreCommands(t *testing.T) {
	keys := map[string]bool{}
	for _, c := range menuChoices {
		if keys[c.key] {
			t.Errorf("menu key %s used twice", c.key)
		}
		keys[c.key] = true
		root := NewRootCmd("test")
		sub, rest, err := root.Find(c.args)
		if err != nil || sub == root {
			t.Errorf("%s: %v is not a command: %v", c.key, c.args, err)
			continue
		}
		if err := sub.ParseFlags(rest); err != nil {
			t.Errorf("%s: %v: %v", c.key, c.args, err)
		}
		if err := sub.ValidateArgs(sub.Flags().Args()); err != nil {
			t.Errorf("%s: %v: %v", c.key, c.args, err)
		}
	}
}

func TestInterruptibleRead(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	in := interruptible{ctx: ctx, r: pr}

	go func() { _, _ = pw.Write([]byte("y\n")) }()
	buf := make([]byte, 8)
	if n, err := in.Read(buf); err != nil || string(buf[:n]) != "y\n" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}

	done := make(chan error, 1)
	go func() { _, err := in.Read(buf); done <- err }() // nothing typed: blocks
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a read waiting for input did not end on Ctrl-C")
	}
}

// TestMenuCtrlC: Ctrl-C while the menu waits for a choice ends sweep as
// interrupted, without waiting for Enter.
func TestMenuCtrlC(t *testing.T) {
	testutil.NewSandbox(t)
	atTerminal(t)
	orig := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return true }
	t.Cleanup(func() { stdinIsTerminal = orig })

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuffer
	cmd := newRootCmd("test", fakeDoctorDeps(macos.AccessGranted))
	cmd.SetIn(interruptible{ctx: ctx, r: pr})
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{})

	code := make(chan int, 1)
	go func() { code <- run(ctx, cmd, &errb) }()
	for !strings.Contains(out.String(), "Choose a number") {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case c := <-code:
		if c != 130 {
			t.Errorf("exit %d, want 130 (interrupted)", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the menu kept waiting after Ctrl-C")
	}
}

func TestMenuEmptyEnter(t *testing.T) {
	testutil.NewSandbox(t)
	atTerminal(t)
	out, _, code := sweepIn(t, "\nq\n", true)
	if code != 0 || strings.Contains(out, "not on the menu") || strings.Count(out, "Choose a number") != 2 {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// syncBuffer is a bytes.Buffer safe to read while another goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
