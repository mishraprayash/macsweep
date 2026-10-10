package apps

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

func infoPlist(id, name string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>CFBundleDocumentTypes</key><array><dict><key>CFBundleTypeName</key><string>nested</string></dict></array>
	<key>CFBundleIdentifier</key><string>` + id + `</string>
	<key>CFBundleName</key><string>` + name + `</string>
	<key>LSUIElement</key><true/>
	<key>NSServices</key><dict><key>CFBundleIdentifier</key><string>com.nested.ignored</string></dict>
</dict></plist>`)
}

// fakeSpotlight knows the given apps and counts its calls.
func fakeSpotlight(calls *int, known ...App) Spotlight {
	return func(context.Context) ([]App, error) {
		*calls++
		return known, nil
	}
}

// bartender is an app in appsFixture: Spotlight knowing it shows Spotlight
// works.
var bartender = App{Path: "/Applications/Setapp/Bartender 5.app", BundleID: "com.surteesstudios.Bartender", Name: "Bartender 5.app"}

// fakeGroups returns the groups declared by apps, keyed by app file name.
func fakeGroups(byApp map[string][]string) AppGroups {
	return func(_ context.Context, app string) ([]string, error) {
		return byApp[filepath.Base(app)], nil
	}
}

func appsFixture(t *testing.T) (*testutil.Sandbox, string) {
	t.Helper()
	s := testutil.NewSandbox(t)
	dir := filepath.Join(s.Dir, "Applications")
	testutil.Build(t, dir, testutil.Tree{
		"Slack.app/Contents/Info.plist":                          testutil.File{Content: infoPlist("com.tinyspeck.slackmacgap", "Slack")},
		"Setapp/Bartender 5.app/Contents/Info.plist":             testutil.File{Content: infoPlist("com.surteesstudios.Bartender", "Bartender 5")},
		"Visual Studio Code.app/Contents/Info.plist":             testutil.File{Content: infoPlist("com.microsoft.VSCode", "Code")},
		"Broken.app/Contents/MacOS/x":                            testutil.File{Size: 1},
		"Deep/er/still/Hidden.app/Contents/Info.plist":           testutil.File{Content: infoPlist("com.too.deep", "Hidden")},
		"Slack.app/Contents/PlugIns/x.appex/Contents/Info.plist": testutil.File{Content: infoPlist("com.inside.bundle", "Inside")},
	})
	return s, dir
}

func TestInventory(t *testing.T) {
	_, dir := appsFixture(t)
	calls := 0
	inv := New(Config{AppDirs: []string{dir, dir + "-missing"}, Spotlight: fakeSpotlight(&calls,
		bartender, App{Path: "/Volumes/USB/Elsewhere.app", BundleID: "com.elsewhere.app", Name: "Elsewhere.app"}, App{Path: "/x/NoID.app"})})

	for id, want := range map[string]bool{
		"com.tinyspeck.slackmacgap":        true,  // installed
		"com.tinyspeck.slackmacgap.helper": true,  // same vendor
		"com.microsoft.errorreporting":     true,  // same vendor as VS Code
		"com.surteesstudios.Bartender":     true,  // two levels down
		"com.elsewhere.other":              true,  // Spotlight knows an app from that vendor
		"com.gone.app":                     false, // nowhere
		"com.too.deep":                     false, // beyond the search depth, and Spotlight does not know it
		"com.inside.bundle":                false, // nested bundles are not apps
		"com.vendor":                       true,  // not a bundle ID: cannot judge
		"com.bad'quote.app":                true,
	} {
		if got := inv.BundleIDInstalled(id); got != want {
			t.Errorf("BundleIDInstalled(%s) = %v, want %v", id, got, want)
		}
	}
	for name, want := range map[string]bool{
		"Slack": true, "slack": true, "Code": true, "Bartender": true, "Bartender 5": true,
		"Elsewhere": true, "NoID": true, "GoneApp": false, "ab": true,
	} {
		if got := inv.NameInstalled(name); got != want {
			t.Errorf("NameInstalled(%s) = %v, want %v", name, got, want)
		}
	}
	if calls != 1 {
		t.Errorf("Spotlight ran %d times, want once", calls)
	}
}

func TestParseSpotlightApps(t *testing.T) {
	out := []byte("/Applications/Google Chrome.app   kMDItemCFBundleIdentifier = com.google.Chrome   kMDItemDisplayName = Google Chrome.app\n" +
		"/Users/me/Downloads/Odd App.app   kMDItemCFBundleIdentifier = (null)   kMDItemDisplayName = (null)\n" +
		"garbage line\n")
	got := ParseSpotlightApps(out)
	want := []App{
		{Path: "/Applications/Google Chrome.app", BundleID: "com.google.Chrome", Name: "Google Chrome.app"},
		{Path: "/Users/me/Downloads/Odd App.app"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parsed %+v", got)
	}
}

// TestComponentsCountAsInstalled: a vendor whose app is gone but whose
// launchd job or privileged helper is still installed is still installed.
func TestComponentsCountAsInstalled(t *testing.T) {
	s, dir := appsFixture(t)
	daemons := filepath.Join(s.Dir, "LaunchDaemons")
	testutil.Build(t, daemons, testutil.Tree{
		"net.tunnelblick.tunnelblick.tunnelblickd.plist": testutil.File{Size: 1},
		"homebrew.mxcl.redis.plist":                      testutil.File{Size: 1},
		"not-an-id.plist":                                testutil.File{Size: 1},
	})
	calls := 0
	inv := New(Config{AppDirs: []string{dir}, ComponentDirs: []string{daemons, daemons + "-missing"},
		Spotlight: fakeSpotlight(&calls, bartender)})
	for id, want := range map[string]bool{
		"net.tunnelblick.tunnelblick": true,
		"homebrew.mxcl.postgresql":    true,
		"com.gone.app":                false,
	} {
		if got := inv.BundleIDInstalled(id); got != want {
			t.Errorf("BundleIDInstalled(%s) = %v, want %v", id, got, want)
		}
	}
}

func TestGroupDeclared(t *testing.T) {
	_, dir := appsFixture(t)
	inv := New(Config{AppDirs: []string{dir}, AppGroups: fakeGroups(map[string][]string{
		"Slack.app": {"group.com.tinyspeck.shared", "TEAMID1234.com.sdk.shared"},
	})})
	for group, want := range map[string]bool{
		"group.com.tinyspeck.shared": true,
		"teamid1234.com.sdk.SHARED":  true, // case-insensitive
		"group.com.gone.app":         false,
	} {
		if got := inv.GroupDeclared(group); got != want {
			t.Errorf("GroupDeclared(%s) = %v, want %v", group, got, want)
		}
	}
}

func TestTracedIDs(t *testing.T) {
	s := testutil.NewSandbox(t)
	lib := filepath.Join(s.Home, "Library")
	testutil.Build(t, lib, testutil.Tree{
		"Preferences/org.m0k.transmission.plist":                     testutil.File{Size: 1},
		"Preferences/com.apple.Transmission.plist":                   testutil.File{Size: 1}, // Apple's: ignored
		"Saved Application State/com.valvesoftware.steam.savedState": testutil.File{Size: 1},
		"Caches/net.tunnelblick.tunnelblick/x":                       testutil.File{Size: 1},
		"Preferences/loginwindow.plist":                              testutil.File{Size: 1}, // not a bundle ID
	})
	inv := New(Config{TraceDirs: []string{
		filepath.Join(lib, "Preferences"), filepath.Join(lib, "Saved Application State"), filepath.Join(lib, "Caches"),
	}})
	for name, want := range map[string]string{
		"Transmission": "org.m0k.transmission",
		"Steam":        "com.valvesoftware.steam",
		"Tunnelblick":  "net.tunnelblick.tunnelblick",
		"loginwindow":  "",
		"Trans":        "", // only whole names match
	} {
		got := strings.Join(inv.TracedIDs(name), ",")
		if got != want {
			t.Errorf("TracedIDs(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestInventoryFailsClosed(t *testing.T) {
	_, dir := appsFixture(t)
	calls := 0
	for name, inv := range map[string]*Inventory{
		// Spotlight does not know even the apps we found: it is not working.
		"spotlight off": New(Config{AppDirs: []string{dir}, Spotlight: fakeSpotlight(&calls,
			App{Path: "/Applications/Other.app", BundleID: "com.other.app"})}),
		"spotlight errors": New(Config{AppDirs: []string{dir}, Spotlight: func(context.Context) ([]App, error) {
			return nil, errors.New("mdfind failed")
		}}),
		"no spotlight": New(Config{AppDirs: []string{dir}}),
		// No apps could be read at all.
		"no apps": New(Config{AppDirs: []string{dir + "-missing"}, Spotlight: fakeSpotlight(&calls, bartender)}),
	} {
		if !inv.BundleIDInstalled("com.gone.app") || !inv.NameInstalled("GoneApp") {
			t.Errorf("%s: an app was reported missing", name)
		}
	}
	for name, inv := range map[string]*Inventory{
		// One app's signature could not be read: its groups are unknown.
		"signature unreadable": New(Config{AppDirs: []string{dir}, AppGroups: func(_ context.Context, app string) ([]string, error) {
			if strings.HasSuffix(app, "Slack.app") {
				return nil, errors.New("codesign failed")
			}
			return nil, nil
		}}),
		"no codesign": New(Config{AppDirs: []string{dir}}),
		"no apps":     New(Config{AppDirs: []string{dir + "-missing"}, AppGroups: fakeGroups(nil)}),
	} {
		if !inv.GroupDeclared("group.com.gone.app") {
			t.Errorf("%s: a group was reported unused", name)
		}
	}
}

func TestBundleAndGroupIDs(t *testing.T) {
	for name, want := range map[string]bool{
		"com.vendor.app": true, "cc.ffitch.shottr": true, "com.microsoft.OneDrive-mac.FinderSync": true,
		"com.vendor": false, "Docker Desktop": false, "com..app": false, "com.vendor.app ": false, "a.b.c/d": false,
	} {
		if got := IsBundleID(name); got != want {
			t.Errorf("IsBundleID(%q) = %v", name, got)
		}
	}
	for group, want := range map[string]string{
		"group.net.whatsapp.WhatsApp.shared":              "net.whatsapp.WhatsApp.shared",
		"6N38VWS5BX.ru.keepcoder.Telegram":                "ru.keepcoder.Telegram",
		"W8F64X92K3.group.com.grammarly.safari.extension": "com.grammarly.safari.extension",
		"group.2TF4LC694H.com.brdsdk.shared":              "com.brdsdk.shared",
		"UBF8T346G9.Office":                               "", // no bundle ID in it
		"group.com.docker":                                "", // two components only
		"2BUA8C4S2C.com.agilebits":                        "",
	} {
		id, ok := GroupBundleID(group)
		if !ok {
			id = ""
		}
		if id != want {
			t.Errorf("GroupBundleID(%s) = %q, want %q", group, id, want)
		}
	}
	if !IsApple("com.apple.Notes") || !IsApple("COM.APPLE.x") || IsApple("com.applesauce.app") {
		t.Error("IsApple misclassifies")
	}
}

func TestParseXMLPlist(t *testing.T) {
	v := parseXMLPlist([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>
		<key>com.apple.security.application-groups</key>
		<array><string>group.a.b.c</string><string>TEAMID1234.d.e.f</string></array>
		<key>nested</key><dict><key>inner</key><string>skip</string><key>arr</key><array><string>skip</string></array></dict>
		<key>dicts</key><array><dict><key>k</key><string>skip</string></dict></array>
		<key>flag</key><true/>
		<key>after</key><string>kept</string>
	</dict></plist>`))
	if got := strings.Join(v["com.apple.security.application-groups"], ","); got != "group.a.b.c,TEAMID1234.d.e.f" {
		t.Errorf("groups = %q", got)
	}
	if v.first("after") != "kept" || v["inner"] != nil || v["k"] != nil || v["arr"] != nil || v["nested"] != nil || v["dicts"] != nil {
		t.Errorf("parsed %v", v)
	}
}

func TestBinaryPlist(t *testing.T) {
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("plutil not available")
	}
	s := testutil.NewSandbox(t)
	p := filepath.Join(s.Dir, "Info.plist")
	if err := os.WriteFile(p, infoPlist("com.binary.app", "Binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-convert", "binary1", p).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v %s", err, out)
	}
	if v := readPlist(p); v.first("CFBundleIdentifier") != "com.binary.app" || v.first("CFBundleName") != "Binary" {
		t.Errorf("binary plist read as %v", v)
	}
}
