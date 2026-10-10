// Package apps knows which applications are installed, so sweep can tell
// data left behind by an uninstalled app from data of an app still in use.
//
// Every answer errs toward "installed": a wrong "not installed" would offer
// an app's data for cleaning. When the app folders cannot be read, Spotlight
// does not work, or an app's code signature cannot be read, the answer is
// "installed".
package apps

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Config says where to look and which tools to use.
type Config struct {
	// AppDirs hold installed apps, searched three levels deep (e.g.
	// /Applications/Setapp/X.app).
	AppDirs []string
	// ComponentDirs hold background parts of installed software named by
	// ID (launchd jobs, privileged helpers). A vendor with one installed
	// counts as installed even when its app is gone.
	ComponentDirs []string
	// TraceDirs hold per-app files named by bundle ID (Preferences,
	// Caches, ...): traces of apps that ran on this Mac.
	TraceDirs []string
	// Spotlight lists the apps it knows anywhere on the Mac. Only when it
	// works (it knows an app found in AppDirs) can an app be reported
	// missing; nil means unavailable.
	Spotlight Spotlight
	// AppGroups reads an app's declared app groups; nil means unavailable,
	// and then every group counts as declared.
	AppGroups AppGroups
}

// Inventory answers questions about installed apps. Each part is read
// lazily, on the first question that needs it, and it is safe for
// concurrent use.
type Inventory struct {
	cfg Config

	once     sync.Once
	appPaths []string        // apps found in AppDirs
	vendors  map[string]bool // vendors of apps, components and Spotlight's apps
	names    map[string]bool // normalized names of apps and Spotlight's apps
	complete bool            // Spotlight works, so an app can be proven missing

	groupsOnce     sync.Once
	groups         map[string]bool // lowercased declared app groups
	groupsComplete bool

	tracesOnce sync.Once
	traces     []string // bundle IDs of apps that left files in TraceDirs
}

// New returns an inventory.
func New(cfg Config) *Inventory {
	return &Inventory{cfg: cfg}
}

// Default is the inventory of /Applications, /System/Applications and
// ~/Applications plus launchd jobs, privileged helpers and every app
// Spotlight knows, with traces from ~/Library and app groups from codesign.
func Default(home string) *Inventory {
	lib := filepath.Join(home, "Library")
	return New(Config{
		AppDirs: []string{"/Applications", "/System/Applications", filepath.Join(home, "Applications")},
		ComponentDirs: []string{
			filepath.Join(lib, "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools",
		},
		TraceDirs: []string{
			filepath.Join(lib, "Preferences"), filepath.Join(lib, "Saved Application State"),
			filepath.Join(lib, "Caches"), filepath.Join(lib, "HTTPStorages"), filepath.Join(lib, "Containers"),
		},
		Spotlight: spotlightApps,
		AppGroups: codesignGroups,
	})
}

// BundleIDInstalled reports whether an app or background component (launchd
// job, privileged helper) from the same vendor as id (its first two
// components, e.g. com.microsoft) is installed. Vendors share helper
// containers between their apps, and app extensions carry their app's ID as
// a prefix, so anything less broad would offer data installed software
// still uses.
func (inv *Inventory) BundleIDInstalled(id string) bool {
	vendor, ok := vendorOf(id)
	if !ok {
		return true
	}
	inv.load()
	return !inv.complete || inv.vendors[vendor]
}

// NameInstalled reports whether an app called name (or containing it, or
// contained in it, ignoring case, spaces and punctuation) is installed.
func (inv *Inventory) NameInstalled(name string) bool {
	if app, ok := AppForFolder(name); ok {
		name = app
	}
	n := normalize(name)
	if len(n) < 3 {
		return true // too short to judge
	}
	inv.load()
	if !inv.complete {
		return true
	}
	for m := range inv.names {
		if m == n || (len(m) >= 4 && len(n) >= 4 && (strings.Contains(m, n) || strings.Contains(n, m))) {
			return true
		}
	}
	return false
}

// GroupDeclared reports whether an installed app declares the app group in
// its code signature. If any app's signature could not be read, every
// group counts as declared.
func (inv *Inventory) GroupDeclared(group string) bool {
	inv.loadGroups()
	return !inv.groupsComplete || inv.groups[strings.ToLower(group)]
}

// TracedIDs returns the bundle IDs of apps that left files in the trace
// folders (e.g. ~/Library/Preferences/org.m0k.transmission.plist) and
// whose last component is name ("Transmission"), ignoring case, spaces and
// punctuation.
func (inv *Inventory) TracedIDs(name string) []string {
	n := normalize(name)
	if n == "" {
		return nil
	}
	inv.loadTraces()
	var out []string
	for _, id := range inv.traces {
		if normalize(lastComponent(id)) == n {
			out = append(out, id)
		}
	}
	return out
}

// folderApps maps app data folder names (lowercased) to the app's name,
// where the two differ.
var folderApps = map[string]string{
	"google":        "Google Chrome",
	"bravesoftware": "Brave Browser",
	"claude-3p":     "Claude",
	"code":          "Visual Studio Code",
}

// AppForFolder returns the app that owns the data folder name (in
// Application Support), when the app's name differs from the folder's.
func AppForFolder(name string) (string, bool) {
	app, ok := folderApps[strings.ToLower(name)]
	return app, ok
}

// load reads the apps in AppDirs, the components in ComponentDirs and the
// apps Spotlight knows. Spotlight counts as working only if it knows one of
// the apps found in AppDirs.
func (inv *Inventory) load() {
	inv.once.Do(func() {
		inv.vendors, inv.names = map[string]bool{}, map[string]bool{}
		var ids []string
		for _, d := range inv.cfg.AppDirs {
			ids = append(ids, inv.walk(d, 3)...)
		}
		for _, id := range ids {
			inv.addVendor(id)
		}
		for _, d := range inv.cfg.ComponentDirs {
			for _, id := range idsIn(d) {
				inv.addVendor(id)
			}
		}
		if inv.cfg.Spotlight == nil || len(ids) == 0 {
			return
		}
		known, err := inv.cfg.Spotlight(context.Background())
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, a := range known {
			seen[strings.ToLower(a.BundleID)] = true
			inv.addVendor(a.BundleID)
			inv.addName(a.Name)
			inv.addName(strings.TrimSuffix(filepath.Base(a.Path), ".app"))
		}
		for _, id := range ids {
			if seen[id] {
				inv.complete = true
				break
			}
		}
	})
}

// walk records the apps under dir and returns their bundle IDs.
func (inv *Inventory) walk(dir string, depth int) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if strings.HasSuffix(strings.ToLower(e.Name()), ".app") {
			if id := inv.add(p); id != "" {
				ids = append(ids, id)
			}
			continue
		}
		if depth > 1 {
			if fi, err := os.Stat(p); err == nil && fi.IsDir() { // follows symlinked folders
				ids = append(ids, inv.walk(p, depth-1)...)
			}
		}
	}
	return ids
}

// add records an app and returns its lowercased bundle ID.
func (inv *Inventory) add(app string) string {
	inv.appPaths = append(inv.appPaths, app)
	inv.addName(strings.TrimSuffix(filepath.Base(app), filepath.Ext(app)))
	info := readPlist(filepath.Join(app, "Contents", "Info.plist"))
	for _, k := range []string{"CFBundleName", "CFBundleDisplayName", "CFBundleExecutable"} {
		inv.addName(info.first(k))
	}
	return strings.ToLower(info.first("CFBundleIdentifier"))
}

func (inv *Inventory) addName(name string) {
	if n := normalize(strings.TrimSuffix(name, ".app")); n != "" {
		inv.names[n] = true
	}
}

func (inv *Inventory) addVendor(id string) {
	if v, ok := vendorOf(id); ok {
		inv.vendors[v] = true
	}
}

// loadGroups reads every installed app's declared app groups, a few apps
// at a time.
func (inv *Inventory) loadGroups() {
	inv.groupsOnce.Do(func() {
		inv.load()
		inv.groups = map[string]bool{}
		if inv.cfg.AppGroups == nil || len(inv.appPaths) == 0 {
			return
		}
		var mu sync.Mutex
		complete := true
		sem := make(chan struct{}, runtime.NumCPU())
		var wg sync.WaitGroup
		for _, app := range inv.appPaths {
			wg.Add(1)
			sem <- struct{}{}
			go func(app string) {
				defer func() { <-sem; wg.Done() }()
				groups, err := inv.cfg.AppGroups(context.Background(), app)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					complete = false
				}
				for _, g := range groups {
					inv.groups[strings.ToLower(g)] = true
				}
			}(app)
		}
		wg.Wait()
		inv.groupsComplete = complete
	})
}

// loadTraces collects the non-Apple bundle IDs named in the trace folders.
func (inv *Inventory) loadTraces() {
	inv.tracesOnce.Do(func() {
		seen := map[string]bool{}
		for _, d := range inv.cfg.TraceDirs {
			for _, id := range idsIn(d) {
				if !IsApple(id) && !seen[id] {
					seen[id] = true
					inv.traces = append(inv.traces, id)
				}
			}
		}
	})
}

// idsIn returns the lowercased bundle IDs that name entries of dir, minus
// the suffixes macOS adds (.plist, .savedState, .binarycookies).
func idsIn(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		id := e.Name()
		for _, suffix := range []string{".plist", ".savedState", ".binarycookies"} {
			id = strings.TrimSuffix(id, suffix)
		}
		if IsBundleID(id) {
			out = append(out, strings.ToLower(id))
		}
	}
	return out
}
