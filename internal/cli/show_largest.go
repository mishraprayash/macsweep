package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// dirDominance: a directory is listed only if no single subdirectory holds
// this share of it, so nested chains show once at their most specific level.
const dirDominance = 0.9

type topDir struct {
	Path         string    `json:"path"`
	Size         uint64    `json:"size_bytes"`
	ApparentSize uint64    `json:"apparent_size_bytes"`
	Files        uint64    `json:"files"`
	Dirs         uint64    `json:"dirs"`
	Newest       time.Time `json:"newest_mtime"`
	Inaccessible bool      `json:"partially_inaccessible"`
	Tier         string    `json:"tier,omitempty"`
}

type topFile struct {
	scanner.FileEntry
	Tier string `json:"tier,omitempty"`
}

// tierOf returns the tier of an exact finding, or "" when the path is not
// itself a finding (it may still lie inside one).
func tierOf(tiers map[string]safety.Tier, path string) string {
	if t, ok := tiers[path]; ok {
		return t.String()
	}
	return ""
}

type topOutput struct {
	Root      string    `json:"root"`
	ScannedAt time.Time `json:"scanned_at"`
	Files     []topFile `json:"files,omitempty"`
	Dirs      []topDir  `json:"dirs,omitempty"`
}

// showLargest lists the largest files and folders in the saved scan, or only
// those under path when one is given.
func showLargest(cmd *cobra.Command, opts *globalOptions, f *showFlags, saved *cache.Scan, path, home string) error {
	n := f.entries(25)
	res := saved.Result
	within := func(p string) bool { return path == "" || isWithin(p, path) }
	if path != "" && !within(res.Root) && !isWithin(path, res.Root) {
		return fmt.Errorf("%s is not inside the last scan (of %s); run 'sweep scan %s' first", path, res.Root, path)
	}
	tiers := map[string]safety.Tier{}
	for _, fd := range saved.Findings {
		tiers[fd.Path] = fd.Tier
	}
	out := topOutput{Root: res.Root, ScannedAt: res.FinishedAt}
	if path != "" {
		out.Root = path
	}
	if !f.onlyDirs {
		out.Files = []topFile{}
		for _, fe := range res.TopFiles {
			if within(fe.Path) && len(out.Files) < n {
				out.Files = append(out.Files, topFile{FileEntry: fe, Tier: tierOf(tiers, fe.Path)})
			}
		}
	}
	if !f.onlyFiles {
		out.Dirs = []topDir{}
		for _, d := range res.Tree.TopDirs(-1, dirDominance) {
			if d.Path == path || !within(d.Path) || len(out.Dirs) == n {
				continue
			}
			out.Dirs = append(out.Dirs, topDir{
				Path: d.Path, Size: d.Size, ApparentSize: d.ApparentSize, Files: d.FileCount,
				Dirs: d.DirCount, Newest: d.Newest, Inaccessible: d.Inaccessible, Tier: tierOf(tiers, d.Path),
			})
		}
	}
	if opts.JSON {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	return renderTop(cmd.OutOrStdout(), out, res, n, opts.Verbose, home)
}

// isWithin reports whether p is dir or inside it (case-insensitively, like APFS).
func isWithin(p, dir string) bool {
	lp, ld := strings.ToLower(filepath.Clean(p)), strings.ToLower(filepath.Clean(dir))
	return lp == ld || strings.HasPrefix(lp, strings.TrimSuffix(ld, "/")+"/")
}

func renderTop(w io.Writer, out topOutput, res *scanner.Result, n int, verbose bool, home string) error {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	under := "From "
	if out.Root != res.Root {
		under = "Under " + shortPath(out.Root, home) + ", from "
	}
	fmt.Fprintf(w, "%s\n", faint.Sprintf("%sscan of %s, %s (%s)", under,
		shortPath(res.Root, home), report.Age(out.ScannedAt, time.Now()), out.ScannedAt.Format("2006-01-02 15:04")))

	if out.Files != nil {
		fmt.Fprintf(w, "\n%s\n", bold.Sprint("Largest files"))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(tw, "SIZE\tAPPARENT\tMODIFIED\tACCESSED\tTIER\tPATH")
		} else {
			fmt.Fprintln(tw, "SIZE\tMODIFIED\tTIER\tPATH")
		}
		for _, f := range out.Files {
			if verbose {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", report.Bytes(f.Size), report.Bytes(f.ApparentSize),
					date(f.MTime), date(f.ATime), tierCell(f.Tier), shortPath(f.Path, home))
			} else {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", report.Bytes(f.Size), date(f.MTime), tierCell(f.Tier), shortPath(f.Path, home))
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if n > len(res.TopFiles) && uint64(len(res.TopFiles)) < res.Stats.Files {
			fmt.Fprintf(w, "%s\n", faint.Sprintf("(the scan kept the %d largest files)", len(res.TopFiles)))
		}
	}

	if out.Dirs != nil {
		fmt.Fprintf(w, "\n%s\n", bold.Sprint("Largest directories"))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SIZE\tFILES\tLAST CHANGE\tTIER\tPATH")
		for _, d := range out.Dirs {
			mark := ""
			if d.Inaccessible {
				mark = " (partly unreadable)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s%s\n", report.Bytes(d.Size), report.Count(d.Files), date(d.Newest), tierCell(d.Tier), shortPath(d.Path, home), mark)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\n", faint.Sprintf("Directories are shown at their most specific level: a folder is omitted when one subfolder holds %.0f%%+ of it.", dirDominance*100))
	}

	if res.Stats.Inaccessible > 0 {
		fmt.Fprintf(w, "\n%s\n", faint.Sprintf("%s unreadable during the scan; see 'sweep doctor'.", pathsCount(res.Stats.Inaccessible)))
	}
	return nil
}

// tierCell renders a tier for a table cell. It stays uncolored because ANSI
// codes in a middle column would throw off tabwriter alignment.
func tierCell(t string) string {
	if t == "" {
		return "-"
	}
	return t
}

func date(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02")
}
