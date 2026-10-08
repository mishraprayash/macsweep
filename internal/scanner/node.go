package scanner

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Node is a directory in the scan tree. Files are not stored as nodes; they
// are aggregated into their directory's totals (the largest files are kept
// separately in Result.TopFiles). The root node's Name is the full root path.
// Every other Name is a single path element.
type Node struct {
	Name string
	// Size is allocated bytes on disk (st_blocks*512) for the directory and
	// everything below it, with hard links counted once.
	Size uint64
	// ApparentSize is the sum of logical file lengths (st_size).
	ApparentSize uint64
	FileCount    uint64 // non-directory entries in the subtree
	DirCount     uint64 // directories in the subtree, excluding this one
	MTime        time.Time
	ATime        time.Time
	// Newest is the most recent file mtime anywhere in the subtree.
	Newest time.Time
	// OwnNewest is the most recent mtime of files directly in this directory.
	OwnNewest time.Time
	// Inaccessible is set when this directory (or part of it) could not be
	// read, so its totals are a lower bound.
	Inaccessible bool
	// Pruned is set when the directory was fully sized but its children were
	// discarded (whole-directory rule match, e.g. node_modules).
	Pruned bool
	// Children are subdirectories sorted by Size, largest first.
	Children []*Node
}

// Walk calls fn for n and every descendant in depth-first order with each
// node's full path. Returning false from fn skips that node's children.
func (n *Node) Walk(fn func(path string, n *Node) bool) {
	n.walk(n.Name, fn)
}

func (n *Node) walk(path string, fn func(string, *Node) bool) {
	if !fn(path, n) {
		return
	}
	for _, c := range n.Children {
		c.walk(joinPath(path, c.Name), fn)
	}
}

// Find returns the node at path (an absolute path under the root), or nil.
func (n *Node) Find(path string) *Node {
	path = filepath.Clean(path)
	root := filepath.Clean(n.Name)
	if path == root {
		return n
	}
	rel, ok := strings.CutPrefix(path, strings.TrimSuffix(root, "/")+"/")
	if !ok {
		return nil
	}
	cur := n
	for _, part := range strings.Split(rel, "/") {
		var next *Node
		for _, c := range cur.Children {
			if c.Name == part {
				next = c
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// Compact removes descendant directories smaller than minSize. Their totals
// stay included in their ancestors. It returns how many nodes were removed.
func (n *Node) Compact(minSize uint64) int {
	removed := 0
	kept := n.Children[:0]
	for _, c := range n.Children {
		if c.Size < minSize {
			removed += 1 + countNodes(c)
			continue
		}
		removed += c.Compact(minSize)
		kept = append(kept, c)
	}
	clear(n.Children[len(kept):])
	n.Children = kept
	return removed
}

func countNodes(n *Node) int {
	c := 0
	for _, ch := range n.Children {
		c += 1 + countNodes(ch)
	}
	return c
}

// mergeInto adds src's totals and children into dst. Both describe the same
// directory, seen from different volumes. It returns the number of
// descendant directories present in both trees, which callers subtract so
// DirCount is not double-counted.
func mergeInto(dst, src *Node) (overlap uint64) {
	dst.Size += src.Size
	dst.ApparentSize += src.ApparentSize
	dst.FileCount += src.FileCount
	dst.DirCount += src.DirCount
	dst.Inaccessible = dst.Inaccessible || src.Inaccessible
	if src.Newest.After(dst.Newest) {
		dst.Newest = src.Newest
	}
	if src.OwnNewest.After(dst.OwnNewest) {
		dst.OwnNewest = src.OwnNewest
	}
	if src.MTime.After(dst.MTime) {
		dst.MTime = src.MTime
	}
	for _, sc := range src.Children {
		var match *Node
		for _, dc := range dst.Children {
			if dc.Name == sc.Name {
				match = dc
				break
			}
		}
		if match == nil {
			dst.Children = append(dst.Children, sc)
			continue
		}
		overlap += 1 + mergeInto(match, sc)
	}
	dst.DirCount -= overlap
	sortChildren(dst)
	return overlap
}

func sortChildren(n *Node) {
	sort.Slice(n.Children, func(i, j int) bool {
		a, b := n.Children[i], n.Children[j]
		if a.Size != b.Size {
			return a.Size > b.Size
		}
		return a.Name < b.Name
	})
}

// DirEntry is a directory with its full path, as returned by TopDirs.
type DirEntry struct {
	Path string `json:"path"`
	*Node
}

// TopDirs returns up to n of the largest directories below the root. A
// directory is skipped when one of its subdirectories holds at least
// dominance (0–1) of its size, so a chain like /Users → /Users/me → ~/Library
// is shown once at its most specific level rather than three times.
func (n *Node) TopDirs(limit int, dominance float64) []DirEntry {
	var all []DirEntry
	n.Walk(func(path string, d *Node) bool {
		if d == n {
			return true
		}
		if len(d.Children) > 0 && float64(d.Children[0].Size) >= dominance*float64(d.Size) {
			return true
		}
		all = append(all, DirEntry{Path: path, Node: d})
		return true
	})
	sort.SliceStable(all, func(i, j int) bool { return all[i].Size > all[j].Size })
	if limit >= 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

func joinPath(dir, name string) string {
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}
