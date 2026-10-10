package macos

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// OpenFiles is a snapshot of the paths the user's processes have open
// (files, directories, working directories and loaded binaries).
type OpenFiles struct {
	paths []string          // lowercased, sorted
	by    map[string]string // lowercased path → command that has it open
}

// ParseOpenFiles parses `lsof -F pcn` output. Paths opened by the process
// with ID self (sweep itself) are ignored.
func ParseOpenFiles(out []byte, self int) *OpenFiles {
	o := &OpenFiles{by: map[string]string{}}
	var cmd string
	skip := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch field, val := line[0], line[1:]; field {
		case 'p':
			pid, _ := strconv.Atoi(val)
			skip, cmd = pid == self, ""
		case 'c':
			cmd = val
		case 'n':
			if skip || !strings.HasPrefix(val, "/") {
				continue // sockets, pipes, devices without a path
			}
			lp := strings.ToLower(val)
			if _, seen := o.by[lp]; !seen {
				o.by[lp] = cmd
				o.paths = append(o.paths, lp)
			}
		}
	}
	sort.Strings(o.paths)
	return o
}

// ListOpenFiles runs `lsof` for the current user's processes. It takes
// well under a second; other users' processes are not visible without root.
func ListOpenFiles(ctx context.Context) (*OpenFiles, error) {
	out, err := exec.CommandContext(ctx, "lsof", "-n", "-P", "-w", "-u", strconv.Itoa(os.Getuid()), "-F", "pcn").Output()
	// lsof exits 1 when some processes could not be inspected; the output is
	// still complete for everything it could see.
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("lsof: %w", err)
	}
	return ParseOpenFiles(out, os.Getpid()), nil
}

// Under returns the command holding path, or something inside it, open.
// A nil OpenFiles holds nothing open.
func (o *OpenFiles) Under(path string) (cmd string, ok bool) {
	if o == nil {
		return "", false
	}
	lp := strings.ToLower(strings.TrimSuffix(path, "/"))
	if c, ok := o.by[lp]; ok {
		return c, true
	}
	prefix := lp + "/"
	i := sort.SearchStrings(o.paths, prefix)
	if i < len(o.paths) && strings.HasPrefix(o.paths[i], prefix) {
		return o.by[o.paths[i]], true
	}
	return "", false
}
