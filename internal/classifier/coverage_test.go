package classifier

import (
	"testing"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

// TestBuiltinCoverage scans a home folder with one example of every common
// space hog (and look-alikes that must not match) and checks which rule
// claims each one.
func TestBuiltinCoverage(t *testing.T) {
	e := newEnv(t, nil)
	f := testutil.File{Size: 100_000}
	as := "Library/Application Support/"
	testutil.Build(t, e.s.Home, testutil.Tree{
		// Electron apps and Chromium browsers.
		as + "Slack/Local State":                                    f,
		as + "Slack/Network Persistent State":                       f,
		as + "Slack/Cache/Cache_Data/x":                             f,
		as + "Slack/Code Cache/js/x":                                f,
		as + "Slack/GPUCache/x":                                     f,
		as + "Slack/Crashpad/settings.dat":                          f,
		as + "Slack/Service Worker/CacheStorage/x":                  f,
		as + "Slack/Service Worker/ScriptCache/x":                   f,
		as + "Slack/IndexedDB/x":                                    f, // site data: not a cache
		as + "Google/Chrome/Local State":                            f,
		as + "Google/Chrome/GrShaderCache/x":                        f,
		as + "Google/Chrome/Default/Preferences":                    f,
		as + "Google/Chrome/Default/DawnCache/x":                    f,
		as + "Notion/Partitions/notion/Preferences":                 f,
		as + "Notion/Partitions/notion/Network Persistent State":    f,
		as + "Notion/Partitions/notion/Cache/x":                     f,
		as + "Code/Local State":                                     f,
		as + "Code/CachedExtensionVSIXs/x.vsix":                     f,
		as + "Code/CachedData/x":                                    f,
		as + "Code/User/workspaceStorage/abc/workspace.json":        testutil.File{Size: 10, MTime: days(200)},
		as + "Code/User/workspaceStorage/abc/state.vscdb":           testutil.File{Size: 100_000, MTime: days(200)},
		as + "Code/User/workspaceStorage/new/workspace.json":        testutil.File{Size: 10, MTime: days(2)},
		as + "Code/User/settings.json":                              f,
		as + "SomeApp/Cache/x":                                      f, // no Chromium marker
		as + "Spotify/PersistentCache/x":                            f,
		as + "Claude-3p/vm_bundles/claudevm.bundle/disk.img":        f,
		"Documents/Local State":                                     f, // outside ~/Library
		"Documents/Cache/x":                                         f,
		"Library/Containers/com.example.app/Data/Library/Caches/x":  f,
		"Library/Containers/com.apple.Notes/Data/Library/Caches/x":  f,
		"Library/Group Containers/ABC.com.example/Library/Caches/x": f,
		"Library/Developer/Xcode/UserData/Previews/x":               f,
		"Library/iTunes/iPhone Software Updates/x.ipsw":             f,
		// Tool caches and models in hidden folders.
		".cache/someTool/x":                                   f,
		".cache/uv/x":                                         f,
		".cache/huggingface/hub/x":                            f,
		".ollama/models/blobs/x":                              f,
		".npm/_npx/x":                                         f,
		".cargo/git/checkouts/x":                              f,
		".gradle/wrapper/dists/gradle-8/x":                    f,
		".nuget/packages/x":                                   f,
		".local/pipx/venvs/tensorflow/x":                      f,
		".agy-profiles/work/Library/Caches/go-build/trim.txt": f,
		".agy-profiles/work/Library/Caches/go-build/00/x":     f,
		// Project build output.
		"code/app/pubspec.yaml":       f,
		"code/app/build/x":            f,
		"code/app/.dart_tool/x":       f,
		"code/svc/pom.xml":            f,
		"code/svc/target/x":           f,
		"code/droid/build.gradle":     f,
		"code/droid/build/x":          f,
		"code/pkg/Package.swift":      f,
		"code/pkg/.build/x":           f,
		"code/py/pyproject.toml":      f,
		"code/py/dist/x.whl":          f,
		"code/game/ProjectSettings/x": f,
		"code/game/Library/x":         f,
		"code/game/Assets/x":          f,
		"code/site/package.json":      f,
		"code/site/.astro/x":          f,
		"code/notes/build/x":          f, // no manifest
	})
	_, fs := e.scan(t)
	got := byPath(fs, e.s.Home)

	want := map[string]string{
		as + "Slack/Cache":                                        "chromium-http-cache",
		as + "Slack/Code Cache":                                   "chromium-gpu-caches",
		as + "Slack/GPUCache":                                     "chromium-gpu-caches",
		as + "Slack/Crashpad":                                     "crashpad-dumps",
		as + "Slack/Service Worker/CacheStorage":                  "chromium-service-worker-cache",
		as + "Google/Chrome/GrShaderCache":                        "chromium-gpu-caches",
		as + "Google/Chrome/Default/DawnCache":                    "chromium-gpu-caches",
		as + "Notion/Partitions/notion/Cache":                     "chromium-http-cache",
		as + "Code/CachedExtensionVSIXs":                          "vscode-caches",
		as + "Code/CachedData":                                    "vscode-caches",
		as + "Code/User/workspaceStorage/abc":                     "vscode-old-workspace-storage",
		as + "Spotify/PersistentCache":                            "spotify-cache",
		as + "Claude-3p/vm_bundles":                               "ai-app-vm-bundles",
		"Library/Containers/com.example.app/Data/Library/Caches":  "sandboxed-app-caches",
		"Library/Containers/com.apple.Notes/Data/Library/Caches":  "apple-sandboxed-caches",
		"Library/Group Containers/ABC.com.example/Library/Caches": "sandboxed-app-caches",
		"Library/Developer/Xcode/UserData/Previews":               "xcode-extra-caches",
		"Library/iTunes/iPhone Software Updates":                  "ios-software-updates",
		".cache/someTool":                                         "xdg-cache",
		".cache/uv":                                               "uv-cache",
		".cache/huggingface":                                      "ml-model-caches",
		".ollama/models":                                          "ml-model-caches",
		".npm/_npx":                                               "npm-cache",
		".cargo/git":                                              "cargo-registry",
		".gradle/wrapper/dists":                                   "gradle-wrapper-dists",
		".nuget/packages":                                         "nuget-packages",
		".local/pipx/venvs/tensorflow":                            "pipx-tools",
		".agy-profiles/work/Library/Caches/go-build":              "go-build-cache-copies",
		"code/app/build":                                          "flutter-build",
		"code/app/.dart_tool":                                     "flutter-build",
		"code/svc/target":                                         "maven-target",
		"code/droid/build":                                        "gradle-build",
		"code/pkg/.build":                                         "swift-build",
		"code/py/dist":                                            "python-build-output",
		"code/game/Library":                                       "unity-library",
		"code/site/.astro":                                        "js-framework-build",
	}
	for p, id := range want {
		if got[p].RuleID != id {
			t.Errorf("%s: rule %q, want %q", p, got[p].RuleID, id)
		}
	}
	for _, p := range []string{
		as + "Slack/IndexedDB", as + "SomeApp/Cache", as + "Code/User/workspaceStorage/new", as + "Code/User",
		"Documents/Cache", "code/notes/build", "code/game/Assets", as + "Slack/Service Worker/ScriptCache",
	} {
		if f, ok := got[p]; ok {
			t.Errorf("%s matched %s; it must be left alone", p, f.RuleID)
		}
	}
}
