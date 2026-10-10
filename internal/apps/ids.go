package apps

import "strings"

// IsBundleID reports whether name looks like a reverse-DNS bundle ID with
// at least three components (com.vendor.app).
func IsBundleID(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.IndexFunc(p, notIDChar) >= 0 {
			return false
		}
	}
	return true
}

func notIDChar(r rune) bool {
	return r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
}

// IsApple reports whether a bundle or group ID belongs to Apple.
func IsApple(id string) bool {
	return strings.HasPrefix(strings.ToLower(id), "com.apple.")
}

// GroupBundleID returns the bundle ID inside an app group name, as used for
// ~/Library/Group Containers entries: "group.com.vendor.app",
// "TEAMID.com.vendor.app", "TEAMID.group.com.vendor.app" or
// "group.TEAMID.com.vendor.app" all give com.vendor.app. ok is false when
// no bundle ID can be read from it (e.g. "UBF8T346G9.Office").
func GroupBundleID(group string) (id string, ok bool) {
	rest := strings.TrimPrefix(group, "group.")
	if team, after, found := strings.Cut(rest, "."); found && isTeamID(team) {
		rest = after
	}
	rest = strings.TrimPrefix(rest, "group.")
	return rest, IsBundleID(rest)
}

// isTeamID reports whether s looks like an Apple developer team ID: ten
// uppercase letters and digits.
func isTeamID(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// Vendor returns the lowercased first two components of a bundle ID, e.g.
// com.microsoft for com.microsoft.Word, or "" if id is not a bundle ID.
func Vendor(id string) string {
	v, _ := vendorOf(id)
	return v
}

func vendorOf(id string) (string, bool) {
	if !IsBundleID(id) {
		return "", false
	}
	parts := strings.SplitN(strings.ToLower(id), ".", 3)
	return parts[0] + "." + parts[1], true
}

// lastComponent returns the part of a bundle ID after its last dot.
func lastComponent(id string) string {
	return id[strings.LastIndexByte(id, '.')+1:]
}

// normalize lowercases s and drops everything but letters and digits.
func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
