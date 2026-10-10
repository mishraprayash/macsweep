package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/report"
)

type showFlags struct {
	n         int
	depth     int
	largest   bool
	onlyFiles bool
	onlyDirs  bool
}

func newShowCmd(opts *globalOptions) *cobra.Command {
	f := &showFlags{}
	cmd := &cobra.Command{
		Use:   "show [path]",
		Short: "Show where the space goes: an overview, a folder, or one path explained",
		Long: `show reads the last scan; it never changes anything.

  sweep show                     overview: categories, "System Data", what is cleanable
  sweep show ~/code              a folder's contents, largest first, with tiers
  sweep show ~/code/app/.next    one path: what it is, which rule matched, and why
  sweep show --largest           the largest files and folders (add a path to narrow it)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.n < 0 || f.depth < 1 || (cmd.Flags().Changed("n") && f.n == 0) {
				return errors.New("-n and --depth must be at least 1")
			}
			home, err := homeDir()
			if err != nil {
				return err
			}
			path := ""
			if len(args) == 1 {
				if path, err = filepath.Abs(expandHome(args[0], home)); err != nil {
					return err
				}
			}
			saved, loadErr := cache.Load(cache.DefaultPath(home))
			switch {
			case f.largest:
				if loadErr != nil {
					return loadErr
				}
				return showLargest(cmd, opts, f, saved, path, home)
			case path == "":
				if loadErr != nil {
					return loadErr
				}
				return showOverview(cmd, opts, f.entries(10), saved, home)
			case loadErr == nil && isBrowsableFolder(saved, path):
				out, err := buildLs(saved, path, f.depth, f.entries(25))
				if err != nil {
					return err
				}
				if opts.JSON {
					return writeJSON(cmd.OutOrStdout(), out)
				}
				renderLs(cmd.OutOrStdout(), out, home)
				return nil
			default:
				if loadErr != nil && !errors.Is(loadErr, cache.ErrNoScan) && opts.Verbose {
					fmt.Fprintf(cmd.ErrOrStderr(), "note: ignoring saved scan: %v\n", loadErr)
				}
				return showPath(cmd, opts, saved, path, home)
			}
		},
	}
	fl := cmd.Flags()
	fl.IntVarP(&f.n, "n", "n", 0, "number of entries to list (default 10 for the overview, 25 otherwise)")
	fl.IntVarP(&f.depth, "depth", "d", 1, "for a folder: how many levels to show")
	fl.BoolVar(&f.largest, "largest", false, "list the largest files and folders")
	fl.BoolVar(&f.onlyFiles, "files", false, "with --largest: only files")
	fl.BoolVar(&f.onlyDirs, "dirs", false, "with --largest: only folders")
	cmd.MarkFlagsMutuallyExclusive("files", "dirs")
	return cmd
}

// isBrowsableFolder reports whether path is a folder the saved scan kept the
// contents of. A folder that is itself a finding is shown as one path.
func isBrowsableFolder(s *cache.Scan, path string) bool {
	if s.Result.Tree.Find(path) == nil {
		return false
	}
	for _, f := range s.Findings {
		if f.IsDir && strings.EqualFold(f.Path, path) {
			return false
		}
	}
	return true
}

// entries is -n, or def when it was not given.
func (f *showFlags) entries(def int) int {
	if f.n == 0 {
		return def
	}
	return f.n
}

func showOverview(cmd *cobra.Command, opts *globalOptions, n int, saved *cache.Scan, home string) error {
	now := time.Now()
	rep := report.Build(saved, report.Options{Home: home, Now: now, TopN: n})
	if opts.JSON {
		return writeJSON(cmd.OutOrStdout(), rep)
	}
	width := 100
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil {
		width = c
	}
	return report.RenderText(cmd.OutOrStdout(), rep, report.TextOptions{
		Home: home, Now: now, Verbose: opts.Verbose, Width: width,
	})
}

func showPath(cmd *cobra.Command, opts *globalOptions, saved *cache.Scan, path, home string) error {
	eng, err := loadEngine(opts, home)
	if err != nil {
		return err
	}
	var data *classifier.ScanData
	if saved != nil {
		data = &classifier.ScanData{Result: saved.Result, Findings: saved.Findings}
	}
	e := eng.classifier().Explain(path, data)
	out := explainOutput{Explanation: e, Clean: cleanVerdict(e)}
	if opts.JSON {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	return renderExplain(cmd.OutOrStdout(), out, home)
}
