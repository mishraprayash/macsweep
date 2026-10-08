package rules

import (
	"fmt"
	"path/filepath"
	"strings"
)

// pathGlob matches absolute paths component by component, case-insensitively.
// "*" and other filepath.Match syntax work within a component; a component
// of exactly "**" matches zero or more components.
type pathGlob struct {
	comps   []string // lowercased
	literal int      // leading components without wildcards (for specificity)
	doubled bool     // contains "**"
	// prefix is the literal leading part ("/users/me/library/caches"), used
	// to reject almost every path without splitting it.
	prefix string
}

func validateGlob(g string) error {
	if !strings.HasPrefix(g, "/") && !strings.HasPrefix(g, "~/") {
		return fmt.Errorf("glob %q must be absolute or start with ~/", g)
	}
	for _, c := range strings.Split(strings.Trim(g, "/"), "/") {
		if c == "" {
			return fmt.Errorf("glob %q has an empty component", g)
		}
		if c == "**" {
			continue
		}
		if strings.Contains(c, "**") {
			return fmt.Errorf("glob %q: ** must be a whole path component", g)
		}
		if _, err := filepath.Match(c, ""); err != nil {
			return fmt.Errorf("glob %q: %w", g, err)
		}
	}
	return nil
}

func compileGlob(abs string) pathGlob {
	g := pathGlob{comps: splitLower(abs)}
	for _, c := range g.comps {
		if c == "**" {
			g.doubled = true
		}
	}
	for _, c := range g.comps {
		if strings.ContainsAny(c, `*?[\`) {
			break
		}
		g.literal++
	}
	g.prefix = "/" + strings.Join(g.comps[:g.literal], "/")
	return g
}

// quick is a cheap, allocation-free pre-check: false means the glob cannot
// match path (an absolute, clean path).
func (g pathGlob) quick(path string) bool {
	if g.literal > 0 {
		n := len(g.prefix)
		if len(path) < n || !strings.EqualFold(path[:n], g.prefix) || (len(path) > n && path[n] != '/') {
			return false
		}
	}
	return g.doubled || strings.Count(path, "/") == len(g.comps)
}

func (g pathGlob) match(comps []string) bool {
	if !g.doubled && len(comps) != len(g.comps) {
		return false
	}
	return matchComps(g.comps, comps)
}

func matchComps(pat, comps []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(comps); i++ {
				if matchComps(pat[1:], comps[i:]) {
					return true
				}
			}
			return false
		}
		if len(comps) == 0 {
			return false
		}
		if ok, err := filepath.Match(pat[0], comps[0]); err != nil || !ok {
			return false
		}
		pat, comps = pat[1:], comps[1:]
	}
	return len(comps) == 0
}

func splitLower(p string) []string {
	p = strings.Trim(strings.ToLower(filepath.Clean(p)), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
