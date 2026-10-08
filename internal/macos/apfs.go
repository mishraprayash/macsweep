package macos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// APFSVolume is one volume in an APFS container.
type APFSVolume struct {
	Device string   `json:"device"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"`
	Used   uint64   `json:"used_bytes"`
}

// HasRole reports whether the volume has the given role (e.g. "Data").
func (v APFSVolume) HasRole(role string) bool {
	for _, r := range v.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// APFSContainer is the container holding the boot volumes. Its volumes
// share its free space, which is why "System Data" is hard to see in Finder.
type APFSContainer struct {
	Reference string       `json:"reference"`
	Capacity  uint64       `json:"capacity_bytes"`
	Free      uint64       `json:"free_bytes"`
	Volumes   []APFSVolume `json:"volumes"`
}

// Used is the space used by all volumes in the container.
func (c APFSContainer) Used() uint64 {
	if c.Free > c.Capacity {
		return 0
	}
	return c.Capacity - c.Free
}

// diskutilJSON is `diskutil apfs list -plist` converted to JSON by plutil.
type diskutilJSON struct {
	Containers []struct {
		ContainerReference string
		CapacityCeiling    uint64
		CapacityFree       uint64
		Volumes            []struct {
			DeviceIdentifier string
			Name             string
			Roles            []string
			CapacityInUse    uint64
		}
	}
}

// ParseAPFSList parses the JSON form of `diskutil apfs list -plist` and
// returns the container that holds the volume with the given device
// identifier (e.g. "disk3s5").
func ParseAPFSList(data []byte, device string) (*APFSContainer, error) {
	var d diskutilJSON
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse diskutil output: %w", err)
	}
	for _, c := range d.Containers {
		for _, v := range c.Volumes {
			if v.DeviceIdentifier != device {
				continue
			}
			out := &APFSContainer{Reference: c.ContainerReference, Capacity: c.CapacityCeiling, Free: c.CapacityFree}
			for _, vv := range c.Volumes {
				out.Volumes = append(out.Volumes, APFSVolume{
					Device: vv.DeviceIdentifier, Name: vv.Name, Roles: vv.Roles, Used: vv.CapacityInUse,
				})
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("no APFS container holds %s", device)
}

// DeviceOf returns the device identifier (e.g. "disk3s5") of the filesystem
// mounted at path.
func DeviceOf(path string) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return "", fmt.Errorf("statfs %s: %w", path, err)
	}
	from := unix.ByteSliceToString(st.Mntfromname[:])
	if !strings.HasPrefix(from, "/dev/") {
		return "", fmt.Errorf("%s is not on a local disk (%s)", path, from)
	}
	return strings.TrimPrefix(from, "/dev/"), nil
}

// ContainerFor runs the read-only commands `diskutil apfs list -plist` and
// `plutil -convert json` and returns the APFS container holding path.
func ContainerFor(ctx context.Context, path string) (*APFSContainer, error) {
	dev, err := DeviceOf(path)
	if err != nil {
		return nil, err
	}
	plist, err := exec.CommandContext(ctx, "diskutil", "apfs", "list", "-plist").Output()
	if err != nil {
		return nil, fmt.Errorf("diskutil apfs list: %w", err)
	}
	conv := exec.CommandContext(ctx, "plutil", "-convert", "json", "-o", "-", "-")
	conv.Stdin = bytes.NewReader(plist)
	data, err := conv.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("plutil: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("plutil: %w", err)
	}
	return ParseAPFSList(data, dev)
}
