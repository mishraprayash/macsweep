package scanner

import (
	"container/heap"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// FileEntry is one of the largest files found.
type FileEntry struct {
	Path         string    `json:"path"`
	Size         uint64    `json:"size_bytes"`
	ApparentSize uint64    `json:"apparent_size_bytes"`
	MTime        time.Time `json:"mtime"`
	ATime        time.Time `json:"atime"`
}

// topFiles keeps the k largest files seen, safely across goroutines. Most
// files are rejected by a lock-free threshold check.
type topFiles struct {
	k   int
	min atomic.Uint64 // smallest size in a full heap; 0 until full
	mu  sync.Mutex
	h   fileHeap
}

func newTopFiles(k int) *topFiles { return &topFiles{k: k} }

// wants reports whether a file of this size could enter the set.
func (t *topFiles) wants(size uint64) bool {
	return t.k > 0 && size > t.min.Load()
}

func (t *topFiles) offer(e FileEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case len(t.h) < t.k:
		heap.Push(&t.h, e)
	case e.Size > t.h[0].Size:
		t.h[0] = e
		heap.Fix(&t.h, 0)
	default:
		return
	}
	if len(t.h) == t.k {
		t.min.Store(t.h[0].Size)
	}
}

// sorted returns the entries largest first.
func (t *topFiles) sorted() []FileEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]FileEntry(nil), t.h...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Path < out[j].Path
	})
	return out
}

type fileHeap []FileEntry

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(FileEntry)) }
func (h *fileHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
