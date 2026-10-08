package scanner

import (
	"math/rand"
	"testing"
)

func tree() *Node {
	// /r (100) ─┬ a (60) ─┬ a1 (55)  ← dominates a
	//           │         └ a2 (5)
	//           └ b (40) ─┬ b1 (20)
	//                     └ b2 (19)
	a := &Node{Name: "a", Size: 60, DirCount: 2, Children: []*Node{{Name: "a1", Size: 55}, {Name: "a2", Size: 5}}}
	b := &Node{Name: "b", Size: 40, DirCount: 2, Children: []*Node{{Name: "b1", Size: 20}, {Name: "b2", Size: 19}}}
	return &Node{Name: "/r", Size: 100, DirCount: 6, Children: []*Node{a, b}}
}

func TestFind(t *testing.T) {
	r := tree()
	for path, want := range map[string]string{"/r": "/r", "/r/a": "a", "/r/b/b2": "b2", "/r/": "/r"} {
		if n := r.Find(path); n == nil || n.Name != want {
			t.Errorf("Find(%q) = %v, want %s", path, n, want)
		}
	}
	for _, p := range []string{"/r/c", "/rr/a", "/other", "/r/a/a1/x"} {
		if n := r.Find(p); n != nil {
			t.Errorf("Find(%q) = %v, want nil", p, n.Name)
		}
	}
	root := &Node{Name: "/", Children: []*Node{{Name: "Users"}}}
	if root.Find("/Users") == nil {
		t.Error("Find under / root failed")
	}
}

func TestWalkPaths(t *testing.T) {
	var got []string
	tree().Walk(func(p string, n *Node) bool {
		got = append(got, p)
		return n.Name != "b" // skip b's children
	})
	want := []string{"/r", "/r/a", "/r/a/a1", "/r/a/a2", "/r/b"}
	if len(got) != len(want) {
		t.Fatalf("Walk = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Walk[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestTopDirs(t *testing.T) {
	got := tree().TopDirs(10, 0.9)
	var paths []string
	for _, d := range got {
		paths = append(paths, d.Path)
	}
	// a is dominated by a1 (55/60 ≥ 0.9) and skipped; the root is never listed.
	want := []string{"/r/a/a1", "/r/b", "/r/b/b1", "/r/b/b2", "/r/a/a2"}
	if len(paths) != len(want) {
		t.Fatalf("TopDirs = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("TopDirs[%d] = %s, want %s", i, paths[i], want[i])
		}
	}
	if n := len(tree().TopDirs(2, 0.9)); n != 2 {
		t.Errorf("limit 2 returned %d", n)
	}
}

func TestCompactKeepsTotals(t *testing.T) {
	r := tree()
	removed := r.Compact(20)
	if removed != 2 { // a2 (5), b2 (19)
		t.Errorf("removed %d, want 2", removed)
	}
	if r.Size != 100 || r.Find("/r/a/a2") != nil || r.Find("/r/b/b1") == nil {
		t.Errorf("unexpected tree after compact")
	}
}

func TestMergeInto(t *testing.T) {
	// System volume: / → usr → bin ; System → Library
	sys := &Node{Name: "/", Size: 10, FileCount: 1, DirCount: 4, Children: []*Node{
		{Name: "usr", Size: 5, DirCount: 1, Children: []*Node{{Name: "bin", Size: 3}}},
		{Name: "System", Size: 4, DirCount: 1, Children: []*Node{{Name: "Library", Size: 2}}},
	}}
	// Data volume: / → usr → local ; Users ; System → Library → Caches
	data := &Node{Name: "/", Size: 20, FileCount: 2, DirCount: 6, Children: []*Node{
		{Name: "usr", Size: 6, DirCount: 1, Children: []*Node{{Name: "local", Size: 4}}},
		{Name: "Users", Size: 8},
		{Name: "System", Size: 5, DirCount: 2, Children: []*Node{{Name: "Library", Size: 4, DirCount: 1, Children: []*Node{{Name: "Caches", Size: 3}}}}},
	}}
	mergeInto(sys, data)

	// Distinct dirs: usr, usr/bin, usr/local, System, System/Library, System/Library/Caches, Users = 7.
	if sys.DirCount != 7 {
		t.Errorf("DirCount = %d, want 7", sys.DirCount)
	}
	if sys.Size != 30 || sys.FileCount != 3 {
		t.Errorf("Size=%d FileCount=%d, want 30 and 3", sys.Size, sys.FileCount)
	}
	if n := sys.Find("/usr"); n == nil || n.Size != 11 || len(n.Children) != 2 {
		t.Errorf("/usr = %+v", n)
	}
	if n := sys.Find("/System/Library/Caches"); n == nil {
		t.Error("/System/Library/Caches missing after merge")
	}
	if sys.Children[0].Name != "System" && sys.Children[0].Name != "usr" {
		t.Errorf("children not sorted by size: first is %s", sys.Children[0].Name)
	}
}

func TestTopFilesHeap(t *testing.T) {
	tf := newTopFiles(10)
	rng := rand.New(rand.NewSource(1))
	var all []uint64
	for i := 0; i < 1000; i++ {
		s := uint64(rng.Intn(1_000_000))
		all = append(all, s)
		if tf.wants(s) {
			tf.offer(FileEntry{Size: s})
		}
	}
	got := tf.sorted()
	// Independent oracle: selection of the 10 largest.
	for i := 0; i < 10; i++ {
		maxIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j] > all[maxIdx] {
				maxIdx = j
			}
		}
		all[i], all[maxIdx] = all[maxIdx], all[i]
		if got[i].Size != all[i] {
			t.Errorf("rank %d: got %d, want %d", i, got[i].Size, all[i])
		}
	}
	if newTopFiles(0).wants(1 << 40) {
		t.Error("k=0 should want nothing")
	}
}
