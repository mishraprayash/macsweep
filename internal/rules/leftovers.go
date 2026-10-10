package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mishraprayash/macsweep/internal/apps"
	"github.com/mishraprayash/macsweep/internal/safety"
)

// LeftoverRuleID is the synthetic rule for data of apps that are no longer
// installed. Match decides membership through matchLeftover, which asks
// Options.Apps, so the scan, explain, and the cleaner's re-check right
// before deleting all agree (a reinstalled app's data is no longer offered).
// The rule's min_age_days also applies, checked after the scan and again
// before deleting.
const LeftoverRuleID = "app-leftovers"

// AppLookup tells which apps are installed (apps.Inventory). Every answer
// must err toward "installed": a wrong "not installed" offers an app's data
// for cleaning.
type AppLookup interface {
	BundleIDInstalled(id string) bool
	NameInstalled(name string) bool
	GroupDeclared(group string) bool
	TracedIDs(name string) []string
}

// naming is how the entries of a leftover root are named.
type naming int

const (
	byBundleID   naming = iota // com.vendor.app
	byGroupID                  // TEAMID.com.vendor.app, group.com.vendor.app
	byIDOrAppDir               // a bundle ID, or a folder named after the app
)

// leftoverDirs are the folders whose entries each belong to one app.
var leftoverDirs = []struct {
	dir    string
	naming naming
}{
	{"~/Library/Application Support", byIDOrAppDir},
	{"~/Library/Containers", byBundleID},
	{"~/Library/Group Containers", byGroupID},
	{"~/Library/WebKit", byBundleID},
	{"~/Library/HTTPStorages", byBundleID},
}

type leftoverRoot struct {
	abs    string
	naming naming
}

func (s *Set) compileLeftovers(lookup AppLookup) {
	c, ok := s.byID[LeftoverRuleID]
	if lookup == nil || !ok || !c.Synthetic || c.User {
		return
	}
	s.apps = lookup
	for _, d := range leftoverDirs {
		s.leftovers = append(s.leftovers, leftoverRoot{abs: s.expand(d.dir), naming: d.naming})
	}
	// Paths other rules leave for the user to review: a leftover must never
	// swallow one (e.g. Steam's installed games).
	for _, r := range s.all {
		if r.Tier < safety.TierReview {
			continue
		}
		for _, p := range r.Match.Path {
			s.reviewPaths = append(s.reviewPaths, strings.ToLower(s.expand(p)))
		}
	}
}

// matchLeftover decides the entries of the leftover roots that no other
// rule matched. An entry is a leftover only with evidence of which app it
// belongs to, and when that app is gone; see app-leftovers in apps.yaml.
func (s *Set) matchLeftover(path string, isDir bool) (Result, bool) {
	if !isDir {
		return Result{}, false
	}
	i := strings.LastIndexByte(path, '/')
	parent, name := path[:i], path[i+1:]
	for _, root := range s.leftovers {
		if len(parent) != len(root.abs) || !strings.EqualFold(parent, root.abs) {
			continue
		}
		reason, ok := s.leftoverReason(root.naming, path, name)
		if !ok || s.holdsReviewPath(path) {
			return Result{}, false
		}
		r := s.byID[LeftoverRuleID].Rule
		reasons := append([]string{reason + " (checked /Applications, ~/Applications and Spotlight)"}, s.sizeAgeReason(r)...)
		return Result{Rule: r, Reason: strings.Join(reasons, "; "), Deferred: r.hasSizeAge()}, true
	}
	return Result{}, false
}

// leftoverReason says why name, an entry of a root named by n, belongs to
// an app that is no longer installed.
func (s *Set) leftoverReason(n naming, path, name string) (string, bool) {
	if strings.HasPrefix(name, ".") || apps.IsApple(name) {
		return "", false
	}
	if n == byGroupID {
		id, ok := apps.GroupBundleID(name)
		if !ok || apps.IsApple(id) || s.apps.GroupDeclared(name) || s.apps.BundleIDInstalled(id) {
			return "", false
		}
		return fmt.Sprintf("app group of %s; no installed app uses this group, and no app from %s is installed", id, apps.Vendor(id)), true
	}
	if apps.IsBundleID(name) {
		if s.apps.BundleIDInstalled(name) {
			return "", false
		}
		return fmt.Sprintf("named after %s, and no app from %s is installed", name, apps.Vendor(name)), true
	}
	if n != byIDOrAppDir || s.apps.NameInstalled(name) {
		return "", false
	}
	if isFile(filepath.Join(path, "Local State")) {
		return fmt.Sprintf("an Electron app's data, and no app named %q is installed", name), true
	}
	ids := s.apps.TracedIDs(name)
	if len(ids) == 0 {
		return "", false // nothing says which app this folder belongs to
	}
	for _, id := range ids {
		if s.apps.BundleIDInstalled(id) {
			return "", false
		}
	}
	return fmt.Sprintf("data of %s, an app that ran on this Mac (it left files in ~/Library) and is no longer installed", ids[0]), true
}

// holdsReviewPath reports whether a rule that leaves things for the user to
// review matches something inside path.
func (s *Set) holdsReviewPath(path string) bool {
	prefix := strings.ToLower(path) + "/"
	for _, p := range s.reviewPaths {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func isFile(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}
