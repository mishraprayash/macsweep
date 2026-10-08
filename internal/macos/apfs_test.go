package macos

import (
	"os"
	"testing"
)

func TestParseAPFSList(t *testing.T) {
	data, err := os.ReadFile("testdata/apfs-list.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseAPFSList(data, "disk3s5")
	if err != nil {
		t.Fatal(err)
	}
	if c.Reference != "disk3" || len(c.Volumes) != 5 || c.Used() != 494384795648-93184000000 {
		t.Errorf("container = %+v", c)
	}
	var data2 APFSVolume
	for _, v := range c.Volumes {
		if v.HasRole("data") {
			data2 = v
		}
	}
	if data2.Name != "Data" || data2.Used != 380000000000 {
		t.Errorf("data volume = %+v", data2)
	}
	if _, err := ParseAPFSList(data, "disk9s9"); err == nil {
		t.Error("unknown device: want error")
	}
	if _, err := ParseAPFSList([]byte("{"), "disk3s5"); err == nil {
		t.Error("bad JSON: want error")
	}
	if (APFSContainer{Capacity: 1, Free: 2}).Used() != 0 {
		t.Error("Used underflow")
	}
}

func TestDeviceOf(t *testing.T) {
	dev, err := DeviceOf(t.TempDir())
	if err != nil {
		t.Skipf("temp dir not on a local disk: %v", err)
	}
	if dev == "" {
		t.Error("empty device")
	}
}

func TestParseLocalSnapshots(t *testing.T) {
	out := []byte("Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-05-101500.local\ncom.apple.TimeMachine.2026-09-30-080000.local\n")
	s := ParseLocalSnapshots(out)
	if len(s) != 2 || s[0].Date.Day() != 30 || s[1].Date.Day() != 5 {
		t.Errorf("snapshots = %+v", s)
	}
	if len(ParseLocalSnapshots([]byte("Snapshots for disk /:\n"))) != 0 {
		t.Error("empty list parsed as non-empty")
	}
}

func TestParseRunningApps(t *testing.T) {
	out := []byte(`1) "Finder" ASN:0x0-0x1001:
    bundleID="com.apple.finder"
2) "Chrome" ASN:0x0-0x2002:
    bundleID="com.google.Chrome"
    bundle path="/Applications/Google Chrome.app"
    executable path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
3) "x" bundleID=[ NULL ]
`)
	apps := ParseRunningApps(out)
	want := []string{"com.apple.finder", "com.google.chrome", "finder", "chrome", "google chrome", "x"}
	for _, w := range want {
		if !apps[w] {
			t.Errorf("%q missing", w)
		}
	}
	if len(apps) != len(want) {
		t.Errorf("apps = %v", apps)
	}
}
