package apps

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"time"
)

// The macOS tools an Inventory uses. Tests pass fakes through Config.

// App is an app bundle Spotlight knows.
type App struct {
	Path, BundleID, Name string
}

// Spotlight lists every app bundle Spotlight has indexed.
type Spotlight func(ctx context.Context) ([]App, error)

// AppGroups returns the app groups an app declares in its code signature
// (com.apple.security.application-groups). An unsigned app declares none.
type AppGroups func(ctx context.Context, app string) ([]string, error)

const toolTimeout = 10 * time.Second

func spotlightApps(ctx context.Context) ([]App, error) {
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "mdfind", "-attr", "kMDItemCFBundleIdentifier", "-attr", "kMDItemDisplayName",
		"kMDItemContentType == 'com.apple.application-bundle'").Output()
	if err != nil {
		return nil, err
	}
	return ParseSpotlightApps(out), nil
}

var spotlightLine = regexp.MustCompile(`^(.+?)\s+kMDItemCFBundleIdentifier = (.*?)\s+kMDItemDisplayName = (.*)$`)

// ParseSpotlightApps parses `mdfind -attr kMDItemCFBundleIdentifier -attr
// kMDItemDisplayName` output, one app per line. "(null)" values are empty.
func ParseSpotlightApps(out []byte) []App {
	var apps []App
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := spotlightLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		a := App{Path: m[1], BundleID: m[2], Name: m[3]}
		if a.BundleID == "(null)" {
			a.BundleID = ""
		}
		if a.Name == "(null)" {
			a.Name = ""
		}
		apps = append(apps, a)
	}
	return apps
}

func codesignGroups(ctx context.Context, app string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "codesign", "-d", "--entitlements", ":-", app)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// An unsigned app cannot use app groups: macOS only grants them to
		// signed code. Any other failure leaves its groups unknown.
		if bytes.Contains(stderr.Bytes(), []byte("not signed at all")) {
			return nil, nil
		}
		return nil, errors.Join(err, errors.New(string(bytes.TrimSpace(stderr.Bytes()))))
	}
	return parseXMLPlist(out)["com.apple.security.application-groups"], nil
}
