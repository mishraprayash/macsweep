package safety

import "strings"

// rootSpec is a hardcoded protected location (SPEC §8.1). Deletion is blocked
// at the root, anywhere below it, and at any ancestor of it (deleting an
// ancestor would delete the root too).
//
// Patterns are absolute or "~/"-relative. Any component may be a
// filepath.Match glob. Matching is case-insensitive because APFS volumes are
// case-insensitive by default.
type rootSpec struct {
	pattern string
	reason  string
	// except, if set, exempts specific paths below the root. It receives the
	// lowercased path components and must only ever narrow the exemption.
	except func(comps []string) bool
}

var protectedRoots = []rootSpec{
	{pattern: "/System", reason: "macOS system volume"},
	{pattern: "/usr", reason: "system binaries and libraries", except: usrLocalCache},
	{pattern: "/bin", reason: "system binaries"},
	{pattern: "/sbin", reason: "system binaries"},
	{pattern: "/private/etc", reason: "system configuration"},
	{pattern: "/private/var/db", reason: "system databases"},
	{pattern: "/private/var/vm", reason: "swap and sleepimage, managed by macOS (shrinks on reboot)"},
	{pattern: "/Library/Apple", reason: "Apple system components"},
	{pattern: "/Applications/*.app", reason: "application bundle"},
	{pattern: "/Applications/*/*.app", reason: "application bundle"},
	{pattern: "~/Applications/*.app", reason: "application bundle"},
	{pattern: "~/Library/Keychains", reason: "keychains (passwords and certificates)"},
	{pattern: "~/Library/Mobile Documents", reason: "iCloud Drive"},
	{pattern: "~/Library/Messages", reason: "Messages history"},
	{pattern: "~/Library/Mail", reason: "Mail data"},
	{pattern: "~/Pictures/*.photoslibrary", reason: "Photos library"},
	{pattern: "~/Library/Application Support/AddressBook", reason: "Contacts"},
	{pattern: "~/Library/Calendars", reason: "Calendars"},
	{pattern: "~/.ssh", reason: "SSH keys"},
	{pattern: "~/.gnupg", reason: "GnuPG keys"},
	{pattern: "~/.aws", reason: "AWS credentials"},
	{pattern: "~/.kube", reason: "Kubernetes credentials"},
	{pattern: "~/.config", reason: "user configuration"},
	{pattern: "~/Library/Logs/sweep", reason: "sweep's own audit log"},
}

// usrLocalCache exempts cache directories under /usr/local (e.g.
// /usr/local/var/cache/...) from the /usr root. /usr/local itself and
// everything without a "cache" component below it stays protected.
func usrLocalCache(comps []string) bool {
	if len(comps) < 3 || comps[0] != "usr" || comps[1] != "local" {
		return false
	}
	for _, c := range comps[2:] {
		if strings.Contains(c, "cache") {
			return true
		}
	}
	return false
}

// protectedComponent reports whether a single path component is protected
// wherever it appears: any .git directory and any .env* file.
func protectedComponent(c string) (string, bool) {
	switch {
	case c == ".git":
		return "git repository data (.git)", true
	case strings.HasPrefix(c, ".env"):
		return "environment/secrets file (.env*)", true
	}
	return "", false
}
