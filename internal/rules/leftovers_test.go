package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

// fakeApps: the listed IDs (by vendor), names and groups are installed or
// declared; traces maps a folder name to the bundle IDs it left behind.
type fakeApps struct {
	vendors, names, groups map[string]bool
	traces                 map[string][]string
}

func (f fakeApps) BundleIDInstalled(id string) bool {
	parts := strings.SplitN(strings.ToLower(id), ".", 3)
	return f.vendors[parts[0]+"."+parts[1]]
}
func (f fakeApps) NameInstalled(n string) bool { return f.names[strings.ToLower(n)] }
func (f fakeApps) GroupDeclared(g string) bool { return f.groups[strings.ToLower(g)] }
func (f fakeApps) TracedIDs(n string) []string { return f.traces[n] }

func TestAppLeftovers(t *testing.T) {
	sb := testutil.NewSandbox(t)
	h := sb.Home
	lib := "Library/"
	testutil.Build(t, h, testutil.Tree{
		lib + "Containers/com.gone.app/Data/x":                    testutil.File{Size: 10},
		lib + "Containers/com.here.app/Data/x":                    testutil.File{Size: 10},
		lib + "Containers/com.apple.Notes/Data/x":                 testutil.File{Size: 10},
		lib + "Containers/Gone/Data/x":                            testutil.File{Size: 10},
		lib + "Group Containers/group.com.gone.app.shared/x":      testutil.File{Size: 10},
		lib + "Group Containers/6N38VWS5BX.com.gone.chat/x":       testutil.File{Size: 10},
		lib + "Group Containers/group.is.workflow.my.app/x":       testutil.File{Size: 10}, // declared by Shortcuts
		lib + "Group Containers/group.com.sdk.shared/x":           testutil.File{Size: 10}, // declared by an app embedding the SDK
		lib + "Group Containers/UBF8T346G9.Office/x":              testutil.File{Size: 10},
		lib + "Group Containers/group.com.apple.notes/x":          testutil.File{Size: 10},
		lib + "Group Containers/group.com.here.app/x":             testutil.File{Size: 10},
		lib + "WebKit/com.gone.app/x":                             testutil.File{Size: 10},
		lib + "HTTPStorages/com.gone.app/x":                       testutil.File{Size: 10},
		lib + "HTTPStorages/com.gone.app.binarycookies":           testutil.File{Size: 10},
		lib + "Application Support/com.gone.tool/db":              testutil.File{Size: 10},
		lib + "Application Support/GoneElectron/Local State":      testutil.File{Size: 10},
		lib + "Application Support/HereElectron/Local State":      testutil.File{Size: 10},
		lib + "Application Support/Transmission/settings.json":    testutil.File{Size: 10},
		lib + "Application Support/Steam/steamapps/common/game/x": testutil.File{Size: 10},
		lib + "Application Support/Sharedname/x":                  testutil.File{Size: 10},
		lib + "Application Support/PlainFolder/settings.json":     testutil.File{Size: 10},
		lib + "Application Support/Electronish/Local State/odd":   testutil.File{Size: 10},
		lib + "Application Support/GoneElectron/Cache/data_0":     testutil.File{Size: 10},
		lib + "Application Support/.hidden.vendor.app/x":          testutil.File{Size: 10},
		"code/com.gone.app/x":                                     testutil.File{Size: 10},
	})
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	apps := fakeApps{
		vendors: map[string]bool{"com.here": true, "com.installed": true},
		names:   map[string]bool{"hereelectron": true},
		groups:  map[string]bool{"group.is.workflow.my.app": true, "group.com.sdk.shared": true},
		traces: map[string][]string{
			"Transmission": {"org.m0k.transmission"},
			"Steam":        {"com.valvesoftware.steam"},
			"Sharedname":   {"com.gone.sharedname", "com.installed.sharedname"},
		},
	}
	s, err := NewSet(Options{Home: h, Rules: b, Apps: apps})
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"Containers/com.gone.app":                    LeftoverRuleID,
		"Group Containers/group.com.gone.app.shared": LeftoverRuleID,
		"Group Containers/6N38VWS5BX.com.gone.chat":  LeftoverRuleID,
		"WebKit/com.gone.app":                        LeftoverRuleID,
		"HTTPStorages/com.gone.app":                  LeftoverRuleID,
		"Application Support/com.gone.tool":          LeftoverRuleID,
		"Application Support/GoneElectron":           LeftoverRuleID,
		"Application Support/Transmission":           LeftoverRuleID, // its settings are still in ~/Library
		"Containers/com.here.app":                    "",             // installed
		"Containers/com.apple.Notes":                 "",             // Apple's own
		"Containers/Gone":                            "",             // not a bundle ID
		"Group Containers/group.is.workflow.my.app":  "",             // an installed app declares the group
		"Group Containers/group.com.sdk.shared":      "",             // likewise
		"Group Containers/UBF8T346G9.Office":         "",             // no bundle ID to check
		"Group Containers/group.com.apple.notes":     "",             // Apple's own
		"Group Containers/group.com.here.app":        "",             // its vendor is installed
		"Application Support/HereElectron":           "",             // installed
		"Application Support/Steam":                  "",             // holds installed games, left for review
		"Application Support/Sharedname":             "",             // one of the apps with that name is installed
		"Application Support/PlainFolder":            "",             // nothing says which app it belongs to
		"Application Support/Electronish":            "",             // "Local State" is a folder, not Chromium's file
		"Application Support/.hidden.vendor.app":     "",
		"Containers/com.gone.app/Data":               "", // only the top folder
		"Application Support/GoneElectron/Cache":     "chromium-http-cache",
	} {
		if got := matchID(s, filepath.Join(h, lib, rel), true); got != want {
			t.Errorf("%s: matched %q, want %q", rel, got, want)
		}
	}
	if got := matchID(s, filepath.Join(h, "code/com.gone.app"), true); got != "" {
		t.Errorf("a folder outside the app data folders matched %q", got)
	}
	if got := matchID(s, filepath.Join(h, lib, "HTTPStorages/com.gone.app.binarycookies"), false); got != "" {
		t.Errorf("a file matched %q", got)
	}

	res, _ := s.Match(Candidate{Path: filepath.Join(h, lib, "Containers/com.gone.app"), IsDir: true})
	if !res.Deferred || !strings.Contains(res.Reason, "no app from com.gone is installed") || !strings.Contains(res.Reason, "untouched for 30+ days") {
		t.Errorf("result = %+v", res)
	}

	// Without an app inventory the rule is off.
	off, err := NewSet(Options{Home: h, Rules: b})
	if err != nil {
		t.Fatal(err)
	}
	if got := matchID(off, filepath.Join(h, lib, "Containers/com.gone.app"), true); got != "" {
		t.Errorf("matched %q without an inventory", got)
	}
}
