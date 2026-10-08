package safety

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome is never created on disk. Lexical tests need a home that cannot
// collide with the real one.
const fakeHome = "/Users/sweep-test-user"

func newGuard(t *testing.T, home string) *Guard {
	t.Helper()
	g, err := NewGuard(home)
	if err != nil {
		t.Fatalf("NewGuard(%q): %v", home, err)
	}
	return g
}

func TestNewGuardRejectsBadHome(t *testing.T) {
	for _, h := range []string{"", "relative/home", "/", "/./"} {
		if _, err := NewGuard(h); err == nil {
			t.Errorf("NewGuard(%q) succeeded, want error", h)
		}
	}
}

func TestProtectedRootPatternsAreValid(t *testing.T) {
	for _, r := range protectedRoots {
		if !strings.HasPrefix(r.pattern, "/") && !strings.HasPrefix(r.pattern, "~/") {
			t.Errorf("pattern %q is neither absolute nor ~/-relative", r.pattern)
		}
		for _, c := range splitLower(strings.TrimPrefix(r.pattern, "~")) {
			if _, err := filepath.Match(c, "x"); err != nil {
				t.Errorf("pattern %q: bad glob component %q: %v", r.pattern, c, err)
			}
		}
	}
}

// instantiate turns a root pattern into a concrete path by expanding ~ and
// replacing glob stars with a plausible name.
func instantiate(home, pattern string) string {
	p := pattern
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, p[2:])
	}
	return strings.ReplaceAll(p, "*", "Example")
}

// TestEveryProtectedRootIsBlocked proves that every hardcoded root refuses
// deletion at the root, below it, above it, and in other letter cases, for
// every deletable tier.
func TestEveryProtectedRootIsBlocked(t *testing.T) {
	g := newGuard(t, fakeHome)
	for _, r := range protectedRoots {
		root := instantiate(fakeHome, r.pattern)
		cases := map[string]string{
			"root":       root,
			"child":      filepath.Join(root, "child"),
			"grandchild": filepath.Join(root, "a", "b", "file.dat"),
			"upper":      strings.ToUpper(filepath.Join(root, "child")),
			"lower":      strings.ToLower(filepath.Join(root, "child")),
			"ancestor":   filepath.Dir(root),
			"trailing/":  root + "/",
		}
		for name, p := range cases {
			if _, ok := g.Protected(p); !ok {
				t.Errorf("%s [%s]: Protected(%q) = false, want true", r.pattern, name, p)
			}
			for _, tier := range []Tier{TierSafe, TierCaution} {
				if err := g.CheckDeletable(p, tier); err == nil {
					t.Errorf("%s [%s]: CheckDeletable(%q, %v) = nil, want error", r.pattern, name, p, tier)
				}
			}
		}
	}
}

func TestProtectedTable(t *testing.T) {
	g := newGuard(t, fakeHome)
	h := fakeHome
	tests := []struct {
		path string
		want bool
	}{
		// Home and its ancestors.
		{h, true},
		{h + "/", true},
		{"/Users", true},
		{"/", true},
		// Component rules.
		{h + "/code/app/.git", true},
		{h + "/code/app/.git/objects/pack/x.pack", true},
		{h + "/code/app/.GIT/config", true},
		{h + "/code/app/.env", true},
		{h + "/code/app/.env.local", true},
		{h + "/code/app/.envrc", true},
		{"/private/tmp/x/.env.production", true},
		// /private aliases.
		{"/etc/hosts", true},
		{"/var/db/receipts", true},
		{"/var/vm/sleepimage", true},
		{"/private/var/vm/swapfile0", true},
		{"/VAR/vm/sleepimage", true},
		// Ancestors of system roots.
		{"/private", true},
		{"/private/var", true},
		{"/Library", true},
		{"/Applications", true},
		{"/Applications/Utilities", true},
		{"/Applications/Utilities/Terminal.app/Contents", true},
		// /usr except cache directories under /usr/local.
		{"/usr/local", true},
		{"/usr/local/bin/node", true},
		{"/usr/lib/libSystem.dylib", true},
		{"/usr/local/var/cache/thing", false},
		{"/usr/local/Caches/foo", false},
		// Mail data versus the Mail Downloads cache.
		{h + "/Library/Mail/V10/x.emlx", true},
		{h + "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/a.pdf", false},
		// Firmlinked data-volume paths stay blocked (under /System).
		{"/System/Volumes/Data/Users/x/Library/Caches/y", true},
		// Legitimate cleanup targets.
		{h + "/Library/Caches/com.example.app", false},
		{h + "/Library/Logs/DiagnosticReports/x.ips", false},
		{h + "/code/app/node_modules", false},
		{h + "/code/app/.venv", false},
		{h + "/Library/Developer/Xcode/DerivedData/App-abc", false},
		{h + "/.Trash/old.dmg", false},
		{h + "/Library/Application Support/Code/Cache", false},
		{"/Library/Logs/DiagnosticReports/x.ips", false},
		{"/private/var/log/system.log", false},
		// Prefix lookalikes must not count as inside a root.
		{h + "/.sshbackup/x", false},
		{h + "/Library/MailArchive/x", false},
		{"/Systemic/x", false},
	}
	for _, tt := range tests {
		reason, got := g.Protected(tt.path)
		if got != tt.want {
			t.Errorf("Protected(%q) = %v (%s), want %v", tt.path, got, reason, tt.want)
		}
		if got && reason == "" {
			t.Errorf("Protected(%q): empty reason", tt.path)
		}
	}
}

// TestAliasesWithoutFilesystem checks the lexical /private alias rewrite on
// its own, independent of symlink resolution on the host.
func TestAliasesWithoutFilesystem(t *testing.T) {
	g := newGuard(t, fakeHome)
	for _, p := range []string{"/etc/hosts", "/var/db/x", "/var/vm/sleepimage", "/ETC/passwd"} {
		if _, ok := g.protectedLexical(canonical(p)); !ok {
			t.Errorf("protectedLexical(canonical(%q)) = false, want true", p)
		}
	}
	for in, want := range map[string]string{
		"/tmp/x":     "/private/tmp/x",
		"/var":       "/private/var",
		"/variable":  "/variable",
		"/etc/../x":  "/x",
		"/Users/a/b": "/Users/a/b",
	} {
		if got := canonical(in); got != want {
			t.Errorf("canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckPath(t *testing.T) {
	g := newGuard(t, fakeHome)
	h := fakeHome
	tests := []struct {
		path string
		ok   bool
	}{
		{"", false},
		{"relative/path", false},
		{"./x", false},
		{"~", false},
		{"~/Library/Caches", false},
		{"/", false},
		{"//", false},
		{"/Library", false},
		{"/Users", false},
		{"/a/../b/c", false},
		{h + "/code/../.ssh/id_rsa", false},
		{h + "/code/app/..", false},
		{"/tmp/a\x00b", false},
		{h, false},
		{h + "/Downloads", false},
		{h + "/Library", false},
		{"/Users/someone-else/Library", false},
		{"/users/someone-else", false},
		{h + "/Downloads/old.dmg", true},
		{h + "/code/app/node_modules", true},
		{"/Users/someone-else/Library/Caches", true},
		{"/Library/Logs", true},
		{"/private/var/log", true},
	}
	for _, tt := range tests {
		err := g.CheckPath(tt.path)
		if (err == nil) != tt.ok {
			t.Errorf("CheckPath(%q) = %v, want ok=%v", tt.path, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrUnsafePath) {
			t.Errorf("CheckPath(%q) error %v is not ErrUnsafePath", tt.path, err)
		}
	}
}

func TestCheckDeletableTiers(t *testing.T) {
	g := newGuard(t, fakeHome)
	p := fakeHome + "/Library/Caches/com.example.app"
	tests := []struct {
		tier Tier
		ok   bool
	}{
		{TierSafe, true},
		{TierCaution, true},
		{TierReview, false},
		{TierProtected, false},
		{TierUnknown, false},
		{Tier(99), false},
	}
	for _, tt := range tests {
		err := g.CheckDeletable(p, tt.tier)
		if (err == nil) != tt.ok {
			t.Errorf("CheckDeletable(tier=%v) = %v, want ok=%v", tt.tier, err, tt.ok)
		}
		if !tt.ok && !errors.Is(err, ErrTier) {
			t.Errorf("CheckDeletable(tier=%v) error %v is not ErrTier", tt.tier, err)
		}
	}
}

func TestExpand(t *testing.T) {
	g := newGuard(t, fakeHome)
	for in, want := range map[string]string{
		"~":                fakeHome,
		"~/Library/Caches": fakeHome + "/Library/Caches",
		"/abs/path":        "/abs/path",
		"~other/x":         "~other/x",
	} {
		if got := g.Expand(in); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

// fsFixture builds a fake home and project under t.TempDir().
type fsFixture struct {
	g    *Guard
	home string
	proj string
}

func newFixture(t *testing.T) fsFixture {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "code", "app")
	for _, d := range []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, "Library", "Keychains"),
		filepath.Join(proj, "node_modules", "left-pad"),
	} {
		mustMkdir(t, d)
	}
	mustWrite(t, filepath.Join(home, ".ssh", "id_ed25519"))
	mustWrite(t, filepath.Join(proj, "package.json"))
	mustWrite(t, filepath.Join(proj, "node_modules", "left-pad", "index.js"))
	return fsFixture{g: newGuard(t, home), home: home, proj: proj}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkedParentIntoProtectedIsBlocked(t *testing.T) {
	f := newFixture(t)
	// ~/code/innocent -> ~/.ssh, so ~/code/innocent/id_ed25519 is really a key.
	link := filepath.Join(f.home, "code", "innocent")
	mustSymlink(t, filepath.Join(f.home, ".ssh"), link)
	p := filepath.Join(link, "id_ed25519")
	if _, ok := f.g.Protected(p); !ok {
		t.Fatalf("Protected(%q) = false, want true (resolves into ~/.ssh)", p)
	}
	if err := f.g.CheckDeletable(p, TierSafe); !errors.Is(err, ErrProtected) {
		t.Fatalf("CheckDeletable = %v, want ErrProtected", err)
	}

	// The same through a deeper chain of links.
	mustSymlink(t, link, filepath.Join(f.home, "code", "chain"))
	if _, ok := f.g.Protected(filepath.Join(f.home, "code", "chain", "id_ed25519")); !ok {
		t.Error("chained symlink into ~/.ssh not blocked")
	}

	// A link resolving to home itself turns a deep-looking path into ~/X.
	mustSymlink(t, f.home, filepath.Join(f.home, "code", "tohome"))
	if err := f.g.CheckPath(filepath.Join(f.home, "code", "tohome", "Documents")); err == nil {
		t.Error("CheckPath through a symlink to home: want too-shallow error")
	}
}

func TestSymlinkedHomeIsResolved(t *testing.T) {
	f := newFixture(t)
	alias := filepath.Join(filepath.Dir(f.home), "home-alias")
	mustSymlink(t, f.home, alias)
	g := newGuard(t, alias)
	// The guard knows home through the alias. The real path must be blocked too.
	if _, ok := g.Protected(filepath.Join(f.home, ".ssh", "id_ed25519")); !ok {
		t.Error("real path of ~/.ssh not protected when home is given via a symlink")
	}
	if _, ok := g.Protected(filepath.Join(alias, ".ssh", "id_ed25519")); !ok {
		t.Error("alias path of ~/.ssh not protected")
	}
}

func matcherFor(id string) Matcher {
	return func(path string, info fs.FileInfo) (string, bool) {
		if info.IsDir() && filepath.Base(path) == "node_modules" {
			return id, true
		}
		return "", false
	}
}

func TestRevalidate(t *testing.T) {
	f := newFixture(t)
	nm := filepath.Join(f.proj, "node_modules")
	fi, err := os.Lstat(nm)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := FileID(fi)
	if !ok {
		t.Fatal("FileID failed")
	}
	good := Target{Path: nm, RuleID: "node-modules", Tier: TierSafe, ScanRoot: f.home, Dev: dev, Ino: ino}

	if err := f.g.Revalidate(good, matcherFor("node-modules")); err != nil {
		t.Fatalf("Revalidate(good) = %v, want nil", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Target)
		matcher Matcher
		want    error
	}{
		{"review tier", func(t *Target) { t.Tier = TierReview }, matcherFor("node-modules"), ErrTier},
		{"protected tier", func(t *Target) { t.Tier = TierProtected }, matcherFor("node-modules"), ErrTier},
		{"nil matcher", nil, nil, ErrChanged},
		{"rule changed", nil, matcherFor("something-else"), ErrChanged},
		{"no rule id", func(t *Target) { t.RuleID = "" }, matcherFor(""), ErrUnsafePath},
		{"empty scan root", func(t *Target) { t.ScanRoot = "" }, matcherFor("node-modules"), ErrUnsafePath},
		{"relative scan root", func(t *Target) { t.ScanRoot = "home" }, matcherFor("node-modules"), ErrUnsafePath},
		{"outside scan root", func(t *Target) { t.ScanRoot = filepath.Join(f.home, "other") }, matcherFor("node-modules"), ErrChanged},
		{"equals scan root", func(t *Target) { t.ScanRoot = nm }, matcherFor("node-modules"), ErrChanged},
		{"scan root prefix lookalike", func(t *Target) { t.ScanRoot = f.proj[:len(f.proj)-1] }, matcherFor("node-modules"), ErrChanged},
		{"inode mismatch", func(t *Target) { t.Ino++ }, matcherFor("node-modules"), ErrChanged},
		{"missing", func(t *Target) { t.Path = filepath.Join(f.proj, "gone", "node_modules") }, matcherFor("node-modules"), ErrChanged},
		{"traversal", func(t *Target) { t.Path = f.proj + "/../app/node_modules" }, matcherFor("node-modules"), ErrUnsafePath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg := good
			if tt.mutate != nil {
				tt.mutate(&tg)
			}
			err := f.g.Revalidate(tg, tt.matcher)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Revalidate = %v, want %v", err, tt.want)
			}
			var v *Violation
			if !errors.As(err, &v) || v.Reason == "" {
				t.Fatalf("error %v is not a *Violation with a reason", err)
			}
		})
	}
}

func TestRevalidateFinalSymlinkRefused(t *testing.T) {
	f := newFixture(t)
	nm := filepath.Join(f.proj, "node_modules")
	if err := os.RemoveAll(nm); err != nil {
		t.Fatal(err)
	}
	// node_modules is now a link to somewhere innocuous-looking.
	other := filepath.Join(f.home, "code", "other")
	mustMkdir(t, other)
	mustSymlink(t, other, nm)
	tg := Target{Path: nm, RuleID: "node-modules", Tier: TierSafe, ScanRoot: f.home}
	if err := f.g.Revalidate(tg, func(string, fs.FileInfo) (string, bool) { return "node-modules", true }); !errors.Is(err, ErrChanged) {
		t.Fatalf("Revalidate on symlink = %v, want ErrChanged", err)
	}
}

// TestRevalidateParentSwappedAfterScan simulates a TOCTOU attack: after the
// scan, the project directory is replaced by a symlink into a protected
// location that contains an object with the same name.
func TestRevalidateParentSwappedAfterScan(t *testing.T) {
	f := newFixture(t)
	nm := filepath.Join(f.proj, "node_modules")
	tg := Target{Path: nm, RuleID: "node-modules", Tier: TierSafe, ScanRoot: f.home}
	match := func(string, fs.FileInfo) (string, bool) { return "node-modules", true }
	if err := f.g.Revalidate(tg, match); err != nil {
		t.Fatalf("pre-swap Revalidate = %v", err)
	}

	mustMkdir(t, filepath.Join(f.home, "Library", "Keychains", "node_modules"))
	if err := os.Rename(f.proj, f.proj+".moved"); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(f.home, "Library", "Keychains"), f.proj)

	err := f.g.Revalidate(tg, match)
	if !errors.Is(err, ErrProtected) {
		t.Fatalf("post-swap Revalidate = %v, want ErrProtected", err)
	}
}

// TestRevalidateParentSwappedOutsideRoot: a parent swapped for a symlink
// leading outside the scan root (but not into a protected root) must still
// be refused.
func TestRevalidateParentSwappedOutsideRoot(t *testing.T) {
	f := newFixture(t)
	scanRoot := filepath.Join(f.home, "code")
	nm := filepath.Join(f.proj, "node_modules")
	tg := Target{Path: nm, RuleID: "node-modules", Tier: TierSafe, ScanRoot: scanRoot}
	match := func(string, fs.FileInfo) (string, bool) { return "node-modules", true }

	elsewhere := filepath.Join(f.home, "Documents", "precious")
	mustMkdir(t, filepath.Join(elsewhere, "node_modules"))
	if err := os.RemoveAll(f.proj); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, elsewhere, f.proj)

	if err := f.g.Revalidate(tg, match); !errors.Is(err, ErrChanged) {
		t.Fatalf("Revalidate = %v, want ErrChanged (outside scan root)", err)
	}
}

func TestTierParseAndText(t *testing.T) {
	for _, s := range []string{"safe", "SAFE", " Caution ", "review", "Protected"} {
		tier, err := ParseTier(s)
		if err != nil {
			t.Errorf("ParseTier(%q): %v", s, err)
			continue
		}
		b, err := tier.MarshalText()
		if err != nil || !strings.EqualFold(string(b), strings.TrimSpace(s)) {
			t.Errorf("MarshalText(%v) = %q, %v", tier, b, err)
		}
	}
	for _, s := range []string{"", "unknown", "safe-ish"} {
		if _, err := ParseTier(s); err == nil {
			t.Errorf("ParseTier(%q) succeeded, want error", s)
		}
	}
	if _, err := TierUnknown.MarshalText(); err == nil {
		t.Error("MarshalText(TierUnknown) succeeded, want error")
	}
	var tier Tier
	if err := tier.UnmarshalText([]byte("caution")); err != nil || tier != TierCaution {
		t.Errorf("UnmarshalText(caution) = %v, %v", tier, err)
	}
}
