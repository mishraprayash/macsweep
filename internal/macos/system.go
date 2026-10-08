package macos

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Snapshot is a local Time Machine snapshot.
type Snapshot struct {
	Name string    `json:"name"`
	Date time.Time `json:"date"`
}

var snapshotDate = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}-\d{6})`)

// ParseLocalSnapshots parses `tmutil listlocalsnapshots /` output, oldest first.
func ParseLocalSnapshots(out []byte) []Snapshot {
	var snaps []Snapshot
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "com.apple.TimeMachine.") {
			continue
		}
		s := Snapshot{Name: line}
		if m := snapshotDate.FindString(line); m != "" {
			if t, err := time.ParseInLocation("2006-01-02-150405", m, time.Local); err == nil {
				s.Date = t
			}
		}
		snaps = append(snaps, s)
	}
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].Date.Before(snaps[j].Date) })
	return snaps
}

// LocalSnapshots lists local Time Machine snapshots of the boot volume using
// the read-only command `tmutil listlocalsnapshots /`.
func LocalSnapshots(ctx context.Context) ([]Snapshot, error) {
	out, err := exec.CommandContext(ctx, "tmutil", "listlocalsnapshots", "/").Output()
	if err != nil {
		return nil, fmt.Errorf("tmutil listlocalsnapshots: %w", err)
	}
	return ParseLocalSnapshots(out), nil
}

// ThinSnapshotsCommand asks macOS to purge as much local snapshot space as it
// can (purge amount far above any disk size, highest urgency).
var ThinSnapshotsCommand = []string{"tmutil", "thinlocalsnapshots", "/", "999999999999999", "4"}

var (
	bundleIDRE   = regexp.MustCompile(`bundleID="([^"]+)"`)
	appNameRE    = regexp.MustCompile(`(?m)^\s*\d+\) "([^"]+)"`)
	bundlePathRE = regexp.MustCompile(`bundle path="[^"]*/([^"/]+)\.app"`)
)

// ParseRunningApps extracts bundle identifiers, app names and bundle names
// from `lsappinfo list`, lowercased.
func ParseRunningApps(out []byte) map[string]bool {
	apps := map[string]bool{}
	for _, re := range []*regexp.Regexp{bundleIDRE, appNameRE, bundlePathRE} {
		for _, m := range re.FindAllSubmatch(out, -1) {
			apps[strings.ToLower(string(m[1]))] = true
		}
	}
	return apps
}

// RunningApps returns the lowercased bundle IDs, names and bundle names
// (e.g. "com.microsoft.vscode", "code", "visual studio code") of running apps, using
// the read-only command `lsappinfo list`.
func RunningApps(ctx context.Context) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, "lsappinfo", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("lsappinfo: %w", err)
	}
	return ParseRunningApps(out), nil
}
