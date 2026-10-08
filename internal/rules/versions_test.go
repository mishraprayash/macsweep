package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/testutil"
)

func versionSet(t *testing.T, home string, env map[string]string) *Set {
	t.Helper()
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(Options{Home: home, Rules: b, Getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func matchID(s *Set, path string, isDir bool) string {
	res, ok := s.Match(Candidate{Path: path, IsDir: isDir})
	if !ok {
		return ""
	}
	return res.Rule.ID
}

func TestNvmOldVersions(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".nvm/alias/default":                   testutil.File{Content: []byte("lts/*\n")},
		".nvm/alias/lts/*":                     testutil.File{Content: []byte("lts/jod\n")},
		".nvm/alias/lts/jod":                   testutil.File{Content: []byte("v22\n")},
		".nvm/versions/node/v18.20.0/bin/node": testutil.File{Size: 10},
		".nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 10},
		".nvm/versions/node/v22.3.0/bin/node":  testutil.File{Size: 10},
		".nvm/versions/node/v22.23.2/bin/node": testutil.File{Size: 10}, // default: newest v22
		".nvm/versions/node/notes/x":           testutil.File{Size: 1},  // not a version
		".nvm/versions/node/v16.0.0":           testutil.Symlink{Target: "v18.20.0"},
	})
	node := filepath.Join(h, ".nvm/versions/node")
	s := versionSet(t, h, map[string]string{"NVM_BIN": filepath.Join(node, "v18.20.0/bin")})

	want := map[string]string{
		"v18.20.0": "",                      // active in this shell
		"v20.11.1": "nvm-old-node-versions", // old
		"v22.3.0":  "nvm-old-node-versions", // old v22
		"v22.23.2": "",                      // default alias
		"notes":    "",
		"v16.0.0":  "", // symlink
	}
	for name, id := range want {
		if got := matchID(s, filepath.Join(node, name), true); got != id {
			t.Errorf("%s: matched %q, want %q", name, got, id)
		}
	}
	res, _ := s.Match(Candidate{Path: filepath.Join(node, "v20.11.1"), IsDir: true})
	if !strings.Contains(res.Reason, "v18.20.0 and v22.23.2") {
		t.Errorf("reason = %q", res.Reason)
	}
	// Not a store entry: deeper paths and other folders do not match.
	for _, p := range []string{filepath.Join(node, "v20.11.1/bin"), filepath.Join(h, ".nvm/versions/v20.11.1")} {
		if id := matchID(s, p, true); id != "" {
			t.Errorf("%s matched %s", p, id)
		}
	}
}

// TestNvmUnknownDefaultKeepsAll: if the version in use cannot be worked out,
// nothing is offered.
func TestNvmUnknownDefaultKeepsAll(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".nvm/alias/default":                   testutil.File{Content: []byte("lts/hydrogen")}, // alias file missing
		".nvm/versions/node/v18.20.0/bin/node": testutil.File{Size: 10},
		".nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 10},
	})
	s := versionSet(t, h, map[string]string{"NVM_BIN": "/somewhere/else/bin"})
	for _, v := range []string{"v18.20.0", "v20.11.1"} {
		if id := matchID(s, filepath.Join(h, ".nvm/versions/node", v), true); id != "" {
			t.Errorf("%s matched %s with no known current version", v, id)
		}
	}
}

func TestNvmAliasForms(t *testing.T) {
	installed := []string{"v18.20.0", "v20.1.0", "v20.11.1", "v22.3.0"}
	sb := testutil.NewSandbox(t)
	alias := filepath.Join(sb.Home, "alias")
	testutil.Build(t, sb.Home, testutil.Tree{
		"alias/default": testutil.File{Content: []byte("work")},
		"alias/work":    testutil.File{Content: []byte("20")},
		"alias/exact":   testutil.File{Content: []byte("v20.1.0")},
		"alias/latest":  testutil.File{Content: []byte("node")},
		"alias/loop":    testutil.File{Content: []byte("loop")},
		"alias/missing": testutil.File{Content: []byte("21")},
	})
	for name, want := range map[string]string{
		"default": "v20.11.1", "exact": "v20.1.0", "latest": "v22.3.0", "loop": "", "missing": "", "nope": "",
	} {
		if got := resolveNvmAlias(alias, name, installed); got != want {
			t.Errorf("%s -> %q, want %q", name, got, want)
		}
	}
}

func TestClaudeOldVersions(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".local/share/claude/versions/2.1.9":   testutil.File{Size: 10},
		".local/share/claude/versions/2.1.282": testutil.File{Size: 10},
		".local/share/claude/versions/2.1.291": testutil.File{Size: 10}, // linked
		".local/share/claude/versions/2.1.294": testutil.File{Size: 10}, // newest (update in progress)
		".local/bin/claude":                    testutil.Symlink{Target: "../share/claude/versions/2.1.291"},
	})
	dir := filepath.Join(h, ".local/share/claude/versions")
	s := versionSet(t, h, nil)
	for name, id := range map[string]string{
		"2.1.9": "claude-code-old-versions", "2.1.282": "claude-code-old-versions", "2.1.291": "", "2.1.294": "",
	} {
		if got := matchID(s, filepath.Join(dir, name), false); got != id {
			t.Errorf("%s: matched %q, want %q", name, got, id)
		}
	}
}

func TestClaudeWithoutLinkKeepsAll(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".local/share/claude/versions/2.1.282": testutil.File{Size: 10},
		".local/share/claude/versions/2.1.294": testutil.File{Size: 10},
		".local/bin/claude":                    testutil.Symlink{Target: "../../other/claude"},
		"other/claude":                         testutil.File{Size: 10},
	})
	s := versionSet(t, h, nil)
	if id := matchID(s, filepath.Join(h, ".local/share/claude/versions/2.1.282"), false); id != "" {
		t.Errorf("matched %s although the linked version is outside the store", id)
	}
}

// TestUserRuleCannotBecomeVersionStore: only the built-in synthetic rule
// enables a store; a user rule cannot reuse the id.
func TestVersionStoreNeedsBuiltinRule(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".local/share/claude/versions/2.1.282": testutil.File{Size: 10},
		".local/share/claude/versions/2.1.294": testutil.File{Size: 10},
		".local/bin/claude":                    testutil.Symlink{Target: "../share/claude/versions/2.1.294"},
	})
	b, _ := Builtin()
	var kept []*Rule
	for _, r := range b {
		if r.ID != "claude-code-old-versions" {
			kept = append(kept, r)
		}
	}
	s, err := NewSet(Options{Home: h, Rules: kept})
	if err != nil {
		t.Fatal(err)
	}
	if id := matchID(s, filepath.Join(h, ".local/share/claude/versions/2.1.282"), false); id != "" {
		t.Errorf("matched %s without the built-in rule", id)
	}
}

func TestPubCacheAndHuggingFace(t *testing.T) {
	h := "/Users/x"
	s := versionSet(t, h, nil)
	for p, id := range map[string]string{
		".pub-cache/hosted":          "dart-pub-cache",
		".pub-cache/git":             "dart-pub-cache",
		".pub-cache/bin":             "", // globally activated tools stay
		".pub-cache/global_packages": "",
		".pub-cache":                 "",
		".cache/huggingface":         "ml-model-caches",
		".cache/opencode":            "xdg-cache",
		".cache/uv":                  "uv-cache",
	} {
		if got := matchID(s, filepath.Join(h, p), true); got != id {
			t.Errorf("%s: matched %q, want %q", p, got, id)
		}
	}
}

func TestClaudeDesktopOldCLIVersions(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		"Library/Application Support/Claude-3p/claude-code/2.1.266/claude":    testutil.File{Size: 10},
		"Library/Application Support/Claude-3p/claude-code/2.1.281/claude":    testutil.File{Size: 10},
		"Library/Application Support/Claude-3p/claude-code-vm/2.1.237/claude": testutil.File{Size: 10}, // only one: kept
	})
	s := versionSet(t, h, nil)
	base := filepath.Join(h, "Library/Application Support/Claude-3p")
	for p, id := range map[string]string{
		"claude-code/2.1.266":    "claude-desktop-old-cli-versions",
		"claude-code/2.1.281":    "",
		"claude-code-vm/2.1.237": "",
	} {
		if got := matchID(s, filepath.Join(base, p), true); got != id {
			t.Errorf("%s: matched %q, want %q", p, got, id)
		}
	}
}

// TestNvmSymlinkedStore: ~/.nvm is a symlink, and $NVM_BIN uses the real
// path. The active version must still be recognised and kept.
func TestNvmSymlinkedStore(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		"tools/nvm/alias/default":                   testutil.File{Content: []byte("22")},
		"tools/nvm/versions/node/v18.20.0/bin/node": testutil.File{Size: 10},
		"tools/nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 10},
		"tools/nvm/versions/node/v22.23.2/bin/node": testutil.File{Size: 10},
		".nvm": testutil.Symlink{Target: "tools/nvm"},
	})
	real := filepath.Join(h, "tools/nvm/versions/node")
	s := versionSet(t, h, map[string]string{"NVM_BIN": filepath.Join(strings.ToUpper(real[:2])+real[2:], "v18.20.0/bin")})
	node := filepath.Join(h, ".nvm/versions/node")
	for name, id := range map[string]string{"v18.20.0": "", "v20.11.1": "nvm-old-node-versions", "v22.23.2": ""} {
		if got := matchID(s, filepath.Join(node, name), true); got != id {
			t.Errorf("%s: matched %q, want %q", name, got, id)
		}
	}
}

// TestNvmFailsClosed: when it is unclear which versions are in use, nothing
// is offered.
func TestNvmFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct{ def, bin string }{
		"default is system":          {"system", "v18.20.0"},
		"NVM_BIN from another store": {"22", "/opt/other-nvm/versions/node/v18.20.0/bin"},
	} {
		t.Run(name, func(t *testing.T) {
			sb := testutil.NewSandbox(t)
			h := sb.Home
			testutil.Build(t, h, testutil.Tree{
				".nvm/alias/default":                   testutil.File{Content: []byte(tc.def)},
				".nvm/versions/node/v18.20.0/bin/node": testutil.File{Size: 10},
				".nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 10},
				".nvm/versions/node/v22.23.2/bin/node": testutil.File{Size: 10},
			})
			node := filepath.Join(h, ".nvm/versions/node")
			bin := tc.bin
			if !filepath.IsAbs(bin) {
				bin = filepath.Join(node, bin, "bin")
			}
			s := versionSet(t, h, map[string]string{"NVM_BIN": bin})
			for _, v := range []string{"v18.20.0", "v20.11.1", "v22.23.2"} {
				if id := matchID(s, filepath.Join(node, v), true); id != "" {
					t.Errorf("%s matched %s", v, id)
				}
			}
		})
	}
}

// TestUserRuleCannotClaimVersionInUse: a broad user rule over a version
// store does not override the detector; the version in use stays unmatched.
func TestUserRuleCannotClaimVersionInUse(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	testutil.Build(t, h, testutil.Tree{
		".nvm/alias/default":                   testutil.File{Content: []byte("22")},
		".nvm/versions/node/v20.11.1/bin/node": testutil.File{Size: 10},
		".nvm/versions/node/v22.23.2/bin/node": testutil.File{Size: 10},
	})
	b, _ := Builtin()
	user := &Rule{ID: "all-node", Category: "Mine", Tier: safety.TierSafe, Description: "d", Source: "u", User: true,
		Match: Match{Glob: StringList{"~/.nvm/versions/node/*"}}}
	s, err := NewSet(Options{Home: h, Rules: append(b, user), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(h, ".nvm/versions/node")
	if id := matchID(s, filepath.Join(node, "v22.23.2"), true); id != "" {
		t.Errorf("version in use matched %s", id)
	}
	if id := matchID(s, filepath.Join(node, "v20.11.1"), true); id != "nvm-old-node-versions" {
		t.Errorf("old version matched %q", id)
	}
}
