//go:build darwin

package scanner

import (
	"encoding/binary"
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getattrlistbulk(2) returns names and attributes for many directory entries
// per call, replacing one lstat(2) per entry. On a typical disk this removes
// most of the scan's system-call time. Go's standard library and x/sys do not
// wrap it, so it is called through libSystem the same way x/sys/unix calls
// libc (see bulk_darwin_*.s).

//go:cgo_import_dynamic libc_getattrlistbulk getattrlistbulk "/usr/lib/libSystem.B.dylib"

var libc_getattrlistbulk_trampoline_addr uintptr //nolint:revive,stylecheck // name fixed by the assembly

//go:linkname syscall_syscall6 syscall.syscall6
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// Attribute bits from <sys/attr.h> not exported by x/sys.
const (
	attrDirMountStatus = 0x4
	attrDirAllocSize   = 0x8
	dirMntStatusMntPt  = 0x1

	vDir = 2
	vLnk = 5
)

// attrlist mirrors struct attrlist.
type attrlist struct {
	bitmapcount uint16
	reserved    uint16
	commonattr  uint32
	volattr     uint32
	dirattr     uint32
	fileattr    uint32
	forkattr    uint32
}

var bulkAttrs = attrlist{
	bitmapcount: unix.ATTR_BIT_MAP_COUNT,
	commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_NAME | unix.ATTR_CMN_DEVID | unix.ATTR_CMN_OBJTYPE |
		unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_ACCTIME | unix.ATTR_CMN_FILEID | unix.ATTR_CMN_ERROR,
	dirattr:  attrDirMountStatus | attrDirAllocSize,
	fileattr: unix.ATTR_FILE_LINKCOUNT | unix.ATTR_FILE_ALLOCSIZE | unix.ATTR_FILE_DATALENGTH,
}

const bulkBufSize = 256 << 10

var bulkBufs = sync.Pool{New: func() any { b := make([]byte, bulkBufSize); return &b }}

// errBulkUnsupported makes the caller fall back to readDirPortable.
var errBulkUnsupported = errors.New("getattrlistbulk not supported")

func getattrlistbulk(fd int, buf []byte) (int, error) {
	r, _, errno := syscall_syscall6(libc_getattrlistbulk_trampoline_addr,
		uintptr(fd), uintptr(unsafe.Pointer(&bulkAttrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

const dirOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// listDirFast opens a directory (relative to its parent's descriptor when
// parent >= 0, which avoids resolving the full path again) and lists it with
// getattrlistbulk. It returns the open descriptor so the caller can open
// subdirectories relative to it; the caller must closeDir it.
func listDirFast(parent int, name, path string) (int, []dirent, error) {
	var fd int
	var err error
	for {
		if parent >= 0 {
			fd, err = unix.Openat(parent, name, dirOpenFlags, 0)
		} else {
			fd, err = unix.Open(path, dirOpenFlags, 0)
		}
		if !errors.Is(err, syscall.EINTR) { // retried like the os package does
			break
		}
	}
	if err != nil {
		return -1, nil, &pathError{op: "open", path: path, err: err}
	}
	ents, err := readDirFD(fd, path)
	return fd, ents, err
}

func closeDir(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

// readDirFast lists path with getattrlistbulk (open, list, close).
func readDirFast(path string) ([]dirent, error) {
	fd, ents, err := listDirFast(-1, "", path)
	closeDir(fd)
	return ents, err
}

// readDirFD lists the open directory fd, falling back to readdir+lstat on
// filesystems without getattrlistbulk support.
func readDirFD(fd int, path string) ([]dirent, error) {
	bp := bulkBufs.Get().(*[]byte)
	defer bulkBufs.Put(bp)
	buf := *bp

	var out []dirent
	for {
		n, err := getattrlistbulk(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EINVAL) {
				return readDirPortable(path)
			}
			return out, &pathError{op: "getattrlistbulk", path: path, err: err}
		}
		if n == 0 {
			return out, nil
		}
		off := 0
		for i := 0; i < n; i++ {
			if off+4 > len(buf) {
				return out, &pathError{op: "getattrlistbulk", path: path, err: errBulkUnsupported}
			}
			length := int(binary.LittleEndian.Uint32(buf[off:]))
			if length <= 0 || off+length > len(buf) {
				return out, &pathError{op: "getattrlistbulk", path: path, err: errBulkUnsupported}
			}
			d, ok := parseEntry(buf[off : off+length])
			off += length
			if !ok {
				continue
			}
			if d.mountPoint && d.err == nil {
				// The listing describes the covered directory; lstat the path
				// to get the mounted filesystem's device.
				if md, err := lstatDirent(joinPath(path, d.name)); err == nil {
					md.name, md.mountPoint = d.name, true
					d = md
				}
			}
			out = append(out, d)
		}
	}
}

// parseEntry decodes one packed entry. Attributes appear only if their bit
// is set in the returned-attributes set, in bit order within each group:
// common, then directory (for directories) or file attributes.
func parseEntry(e []byte) (dirent, bool) {
	var d dirent
	p := 4 // skip length
	u32 := func() uint32 { v := binary.LittleEndian.Uint32(e[p:]); p += 4; return v }
	u64 := func() uint64 { v := binary.LittleEndian.Uint64(e[p:]); p += 8; return v }
	ts := func() time.Time {
		sec := int64(binary.LittleEndian.Uint64(e[p:]))
		nsec := int64(binary.LittleEndian.Uint64(e[p+8:]))
		p += 16
		return time.Unix(sec, nsec)
	}
	if len(e) < 4+20 {
		return d, false
	}
	common, _, dirAttrs, fileAttrs := u32(), u32(), u32(), u32()
	u32() // forkattr

	if common&unix.ATTR_CMN_NAME != 0 {
		ref := p
		nameOff := int(int32(u32()))
		nameLen := int(u32())
		start := ref + nameOff
		if nameLen > 0 && start >= 0 && start+nameLen <= len(e) {
			d.name = string(e[start : start+nameLen-1]) // drop the trailing NUL
		}
	}
	if d.name == "" {
		return d, false
	}
	if common&unix.ATTR_CMN_DEVID != 0 {
		d.dev = uint64(u32())
	}
	var objType uint32
	if common&unix.ATTR_CMN_OBJTYPE != 0 {
		objType = u32()
	}
	if common&unix.ATTR_CMN_MODTIME != 0 {
		d.mtime = ts()
	}
	if common&unix.ATTR_CMN_ACCTIME != 0 {
		d.atime = ts()
	}
	if common&unix.ATTR_CMN_FILEID != 0 {
		d.ino = u64()
	}
	if common&unix.ATTR_CMN_ERROR != 0 {
		if errno := syscall.Errno(u32()); errno != 0 {
			d.err = errno
			return d, true
		}
	}
	d.isDir = objType == vDir
	d.isLink = objType == vLnk
	if d.isDir {
		if dirAttrs&attrDirMountStatus != 0 {
			d.mountPoint = u32()&dirMntStatusMntPt != 0
		}
		if dirAttrs&attrDirAllocSize != 0 {
			d.alloc = u64()
		}
		return d, true
	}
	if fileAttrs&unix.ATTR_FILE_LINKCOUNT != 0 {
		d.nlink = u32()
	}
	if fileAttrs&unix.ATTR_FILE_ALLOCSIZE != 0 {
		d.alloc = u64()
	}
	if fileAttrs&unix.ATTR_FILE_DATALENGTH != 0 {
		d.size = u64()
	}
	return d, true
}

type pathError struct {
	op, path string
	err      error
}

func (e *pathError) Error() string { return e.op + " " + e.path + ": " + e.err.Error() }
func (e *pathError) Unwrap() error { return e.err }
