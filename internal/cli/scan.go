package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// minCachedDirSize: directories smaller than this are folded into their
// parent's totals in the saved scan, which keeps the cache small on a full
// disk. Totals are unaffected.
const minCachedDirSize = 1_000_000

type childSize struct {
	Path  string  `json:"path"`
	Size  uint64  `json:"size_bytes"`
	Files uint64  `json:"files"`
	Share float64 `json:"share"`
}

type scanSummary struct {
	Root               string             `json:"root"`
	StartedAt          time.Time          `json:"started_at"`
	FinishedAt         time.Time          `json:"finished_at"`
	DurationSeconds    float64            `json:"duration_seconds"`
	Workers            int                `json:"workers"`
	Walks              []scanner.Walk     `json:"walks"`
	Stats              scanner.Stats      `json:"stats"`
	Largest            []childSize        `json:"largest"`
	Skipped            []scanner.Skip     `json:"skipped"`
	InaccessibleSample []string           `json:"inaccessible_sample"`
	ErrorsSample       []string           `json:"errors_sample"`
	Tiers              []report.TierTotal `json:"tiers"`
	CachePath          string             `json:"cache_path"`
}

func newScanCmd(opts *globalOptions) *cobra.Command {
	var workers int
	var crossDevice bool
	var cpuProfile string
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan the disk (default /) and save the results",
		Long: "Scan measures allocated disk usage under path (default: the whole disk) and saves\n" +
			"the result so report, top, and clean can use it. Scanning only reads; it never\n" +
			"modifies anything except its own cache file.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			root := "/"
			if len(args) == 1 {
				if root, err = filepath.Abs(expandHome(args[0], home)); err != nil {
					return err
				}
			}
			if cpuProfile != "" {
				stop, err := startCPUProfile(cpuProfile)
				if err != nil {
					return err
				}
				defer stop()
			}
			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, home, scanner.Options{
				Root:        root,
				Workers:     workers,
				CrossDevice: crossDevice,
			})
		},
	}
	cmd.Flags().IntVar(&workers, "workers", 0, "concurrent directory readers (default 2×CPU cores)")
	cmd.Flags().BoolVar(&crossDevice, "cross-device", false, "descend into other mounted filesystems (network mounts are always skipped)")
	cmd.Flags().StringVar(&cpuProfile, "cpuprofile", "", "write a CPU profile (for performance work)")
	_ = cmd.Flags().MarkHidden("cpuprofile")
	return cmd
}

func runScan(ctx context.Context, stdout, stderr io.Writer, opts *globalOptions, home string, so scanner.Options) error {
	eng, err := loadEngine(opts, home)
	if err != nil {
		return err
	}
	cls := eng.classifier()
	// Disk totals, the APFS volume layout and snapshots are gathered while the
	// scan runs, so the extra commands add no time.
	probed := make(chan systemInfo, 1)
	go func() { probed <- systemProbe(ctx) }()
	progress := newProgressLine(stderr)
	so.Progress = progress.update
	so.Visit = cls.Visit
	res, err := scanner.Scan(ctx, so)
	progress.clear()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("scan cancelled; the previous saved scan was left unchanged: %w", err)
		}
		return err
	}

	findings := cls.Findings(res) // before compaction: needs the full tree
	sum := summarize(res)
	sum.Tiers = report.TierTotals(findings)
	res.Tree.Compact(minCachedDirSize)
	sum.CachePath = cache.DefaultPath(home)
	info := <-probed
	saved := &cache.Scan{Result: res, Findings: findings, Disk: info.disk, Container: info.container, Snapshots: info.snapshots}
	if err := cache.Save(sum.CachePath, saved); err != nil {
		return err
	}

	if opts.JSON {
		return writeJSON(stdout, sum)
	}
	return renderScan(stdout, sum, opts.Verbose, home)
}

func summarize(res *scanner.Result) scanSummary {
	s := scanSummary{
		Root:               res.Root,
		StartedAt:          res.StartedAt,
		FinishedAt:         res.FinishedAt,
		DurationSeconds:    res.FinishedAt.Sub(res.StartedAt).Seconds(),
		Workers:            res.Workers,
		Walks:              res.Walks,
		Stats:              res.Stats,
		Skipped:            nonNil(res.Skipped),
		InaccessibleSample: nonNil(head(res.Inaccessible, 50)),
		ErrorsSample:       nonNil(head(res.Errors, 50)),
	}
	total := res.Tree.Size
	share := func(n uint64) float64 {
		if total == 0 {
			return 0
		}
		return float64(n) / float64(total)
	}
	var inChildren, filesInChildren uint64
	for _, c := range res.Tree.Children {
		inChildren += c.Size
		filesInChildren += c.FileCount
	}
	for _, c := range head(res.Tree.Children, 10) {
		p := filepath.Join(res.Root, c.Name)
		s.Largest = append(s.Largest, childSize{Path: p, Size: c.Size, Files: c.FileCount, Share: share(c.Size)})
	}
	if own := total - inChildren; own > 0 && res.Tree.FileCount > filesInChildren {
		s.Largest = append(s.Largest, childSize{
			Path: "(files directly in " + res.Root + ")", Size: own,
			Files: res.Tree.FileCount - filesInChildren, Share: share(own),
		})
	}
	s.Largest = nonNil(s.Largest)
	return s
}

func renderScan(w io.Writer, s scanSummary, verbose bool, home string) error {
	bold, yellow := color.New(color.Bold), color.New(color.FgYellow)
	dur := time.Duration(s.DurationSeconds * float64(time.Second))
	if dur < time.Second {
		dur = dur.Round(time.Millisecond)
	} else {
		dur = dur.Round(100 * time.Millisecond)
	}

	fmt.Fprintf(w, "%s %s in %s\n", bold.Sprint("Scanned"), shortPath(s.Root, home), dur)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if verbose {
		fmt.Fprintf(tw, "  On disk\t%s\t(apparent size %s)\n", report.Bytes(s.Stats.Size), report.Bytes(s.Stats.ApparentSize))
	} else {
		fmt.Fprintf(tw, "  On disk\t%s\n", report.Bytes(s.Stats.Size))
	}
	fmt.Fprintf(tw, "  Files\t%s\n", report.Count(s.Stats.Files))
	fmt.Fprintf(tw, "  Directories\t%s\n", report.Count(s.Stats.Dirs))
	if s.Stats.HardLinksDeduped > 0 {
		fmt.Fprintf(tw, "  Hard links\t%s extra links counted once\n", report.Count(s.Stats.HardLinksDeduped))
	}
	if s.Stats.Symlinks > 0 {
		fmt.Fprintf(tw, "  Symlinks\t%s (not followed)\n", report.Count(s.Stats.Symlinks))
	}
	if verbose {
		fmt.Fprintf(tw, "  Workers\t%d\n", s.Workers)
		for _, wk := range s.Walks {
			fmt.Fprintf(tw, "  Walked\t%s (shown as %s)\n", wk.Path, wk.DisplayAs)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(s.Largest) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold.Sprintf("Largest under %s", shortPath(s.Root, home)))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
		for _, c := range s.Largest {
			fmt.Fprintf(tw, "  %s\t%.0f%%\t  %s\n", report.Bytes(c.Size), c.Share*100, relPath(c.Path, s.Root))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(s.Tiers) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold.Sprint("By risk tier"))
		if err := renderTierTotals(w, s.Tiers); err != nil {
			return err
		}
	}

	fmt.Fprintln(w)
	if s.Stats.Inaccessible > 0 {
		fmt.Fprintf(w, "%s %s unreadable; totals are a lower bound. Grant Full Disk Access, see 'sweep doctor'.\n",
			yellow.Sprint("!"), pathsCount(s.Stats.Inaccessible))
		if verbose {
			for _, p := range s.InaccessibleSample {
				fmt.Fprintf(w, "    %s\n", shortPath(p, home))
			}
		}
	}
	if s.Stats.Errors > 0 {
		fmt.Fprintf(w, "%s %s could not be read due to errors.\n", yellow.Sprint("!"), pathsCount(s.Stats.Errors))
		if verbose {
			for _, e := range s.ErrorsSample {
				fmt.Fprintf(w, "    %s\n", e)
			}
		}
	}
	if len(s.Skipped) > 0 {
		if verbose {
			fmt.Fprintln(w, "Skipped:")
			for _, sk := range s.Skipped {
				fmt.Fprintf(w, "    %s  (%s)\n", shortPath(sk.Path, home), sk.Reason)
			}
		} else {
			fmt.Fprintf(w, "Skipped %d paths (other volumes, mounts, or firmlinks counted elsewhere); --verbose lists them.\n", len(s.Skipped))
		}
	}
	fmt.Fprintf(w, "Note: %s\n", report.ClonesNote)
	fmt.Fprintf(w, "%s\n", report.UnitsNote)
	fmt.Fprintf(w, "\nSaved to %s. Next: %s or %s\n", shortPath(s.CachePath, home), bold.Sprint("sweep top"), bold.Sprint("sweep explain <path>"))
	return nil
}

// relPath shows p relative to root (the section header already names root).
func relPath(p, root string) string {
	if rel, err := filepath.Rel(root, p); err == nil && filepath.IsLocal(rel) {
		return rel
	}
	return p
}

func pathsCount(n uint64) string {
	if n == 1 {
		return "1 path"
	}
	return report.Count(n) + " paths"
}

func head[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// nonNil makes JSON emit [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

type systemInfo struct {
	disk      *macos.DiskUsage
	container *macos.APFSContainer
	snapshots []macos.Snapshot
}

// systemProbe records disk totals, the APFS volume breakdown and local Time
// Machine snapshots at scan time, using read-only commands. Failures leave
// fields empty; the report says what is missing. Tests replace it so they
// never run diskutil or tmutil.
var systemProbe = func(ctx context.Context) systemInfo {
	var info systemInfo
	vol := macos.SystemVolume()
	if du, err := macos.Statfs(vol); err == nil {
		info.disk = &du
	}
	if c, err := macos.ContainerFor(ctx, vol); err == nil {
		info.container = c
	}
	if s, err := macos.LocalSnapshots(ctx); err == nil {
		info.snapshots = s
	}
	return info
}

func startCPUProfile(path string) (stop func(), err error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { pprof.StopCPUProfile(); _ = f.Close() }, nil
}
