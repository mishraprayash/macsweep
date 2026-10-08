package cli

import (
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/report"
)

func newReportCmd(opts *globalOptions) *cobra.Command {
	var top int
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Explain where the space goes, using the last scan",
		Long: "report renders the last scan: disk overview, categories, what macOS calls\n" +
			"\"System Data\", reclaimable space per tier, cleanup candidates, stale projects,\n" +
			"items for you to review, protected items, and suggested next steps.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			saved, err := cache.Load(cache.DefaultPath(home))
			if err != nil {
				return err
			}
			now := time.Now()
			rep := report.Build(saved, report.Options{Home: home, Now: now, TopN: top})
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
		},
	}
	cmd.Flags().IntVar(&top, "top", 20, "number of cleanup candidates to list")
	return cmd
}
