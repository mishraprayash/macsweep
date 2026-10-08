package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

type lsRow struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Depth     int    `json:"depth"`
	IsDir     bool   `json:"is_dir"`
	Size      uint64 `json:"size_bytes"`
	Files     uint64 `json:"files"`
	Cleanable uint64 `json:"cleanable_bytes"`
	Tier      string `json:"tier,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Stale     bool   `json:"stale,omitempty"`
}

type lsOutput struct {
	Path      string                      `json:"path"`
	Size      uint64                      `json:"size_bytes"`
	Files     uint64                      `json:"files"`
	ScannedAt time.Time                   `json:"scanned_at"`
	Rows      []lsRow                     `json:"rows"`
	OwnFiles  uint64                      `json:"files_here_bytes"`
	Hidden    int                         `json:"hidden_rows"`
	Cleanable map[string]report.TierTotal `json:"cleanable"`
}

func newLsCmd(opts *globalOptions) *cobra.Command {
	var depth, limit int
	cmd := &cobra.Command{
		Use:   "ls [path]",
		Short: "Browse the last scan: what is inside a folder and what is cleanable",
		Long: "ls lists a folder's contents from the last scan, largest first, with each\n" +
			"item's tier and how much of it is cleanable. Use it to inspect a folder before\n" +
			"running 'sweep clean --under <folder>'. It reads only the saved scan.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			saved, err := cache.Load(cache.DefaultPath(home))
			if err != nil {
				return err
			}
			path := saved.Result.Root
			if len(args) == 1 {
				if path, err = filepath.Abs(expandHome(args[0], home)); err != nil {
					return err
				}
			}
			out, err := buildLs(saved, path, depth, limit)
			if err != nil {
				return err
			}
			if opts.JSON {
				return writeJSON(cmd.OutOrStdout(), out)
			}
			renderLs(cmd.OutOrStdout(), out, home)
			return nil
		},
	}
	cmd.Flags().IntVarP(&depth, "depth", "d", 1, "how many levels to show")
	cmd.Flags().IntVarP(&limit, "n", "n", 25, "entries per folder")
	return cmd
}

func buildLs(s *cache.Scan, path string, depth, limit int) (*lsOutput, error) {
	if depth < 1 || limit < 1 {
		return nil, fmt.Errorf("--depth and -n must be at least 1")
	}
	path = filepath.Clean(path)
	tree := s.Result.Tree
	findings := map[string]classifier.Finding{}
	for _, f := range s.Findings {
		findings[strings.ToLower(f.Path)] = f
	}

	node := tree.Find(path)
	if node == nil {
		return nil, lsMissing(s, path)
	}
	if f, ok := findings[strings.ToLower(path)]; ok && f.IsDir {
		return nil, fmt.Errorf("%s is a single %s finding (%s, rule %s); its contents were not kept. Try 'sweep explain %s'",
			path, f.Tier, report.Bytes(f.Size), f.RuleID, path)
	}

	out := &lsOutput{Path: path, Size: node.Size, Files: node.FileCount, ScannedAt: s.Result.FinishedAt, Cleanable: map[string]report.TierTotal{}}
	lp := strings.ToLower(path) + "/"
	for _, f := range s.Findings {
		if strings.HasPrefix(strings.ToLower(f.Path), lp) {
			t := out.Cleanable[f.Tier.String()]
			t.Tier, t.Size, t.Count = f.Tier, t.Size+f.Size, t.Count+1
			out.Cleanable[f.Tier.String()] = t
		}
	}
	cleanableUnder := func(p string) uint64 {
		var n uint64
		pre := strings.ToLower(p)
		for _, f := range s.Findings {
			lf := strings.ToLower(f.Path)
			if f.Tier.Deletable() && (lf == pre || strings.HasPrefix(lf, pre+"/")) {
				n += f.Size
			}
		}
		return n
	}

	var walk func(n *scanner.Node, p string, level int)
	walk = func(n *scanner.Node, p string, level int) {
		type entry struct {
			row  lsRow
			node *scanner.Node
		}
		var entries []entry
		var inChildren uint64
		for _, c := range n.Children {
			cp := filepath.Join(p, c.Name)
			inChildren += c.Size
			r := lsRow{Path: cp, Name: c.Name, Depth: level, IsDir: true, Size: c.Size, Files: c.FileCount, Cleanable: cleanableUnder(cp)}
			child := c
			if f, ok := findings[strings.ToLower(cp)]; ok {
				r.Tier, r.RuleID, r.Stale = f.Tier.String(), f.RuleID, f.Stale
				child = nil // a finding is one unit; do not descend
			}
			entries = append(entries, entry{r, child})
		}
		// File findings directly in this folder (e.g. an old download).
		for _, f := range s.Findings {
			if !f.IsDir && strings.EqualFold(filepath.Dir(f.Path), p) {
				cl := uint64(0)
				if f.Tier.Deletable() {
					cl = f.Size
				}
				entries = append(entries, entry{row: lsRow{
					Path: f.Path, Name: filepath.Base(f.Path), Depth: level, Size: f.Size, Files: 1,
					Cleanable: cl, Tier: f.Tier.String(), RuleID: f.RuleID,
				}})
			}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].row.Size > entries[j].row.Size })
		if level == 0 {
			out.OwnFiles = n.Size - min(n.Size, inChildren)
		}
		for i, e := range entries {
			if i == limit {
				if level == 0 {
					out.Hidden = len(entries) - limit
				}
				break
			}
			out.Rows = append(out.Rows, e.row)
			if e.node != nil && level+1 < depth {
				walk(e.node, e.row.Path, level+1)
			}
		}
	}
	walk(node, path, 0)
	return out, nil
}

// lsMissing explains why a path has no node in the saved tree.
func lsMissing(s *cache.Scan, path string) error {
	root := filepath.Clean(s.Result.Root)
	lp := strings.ToLower(path)
	lr := strings.ToLower(root)
	if lp != lr && !strings.HasPrefix(lp, strings.TrimSuffix(lr, "/")+"/") {
		return fmt.Errorf("%s is not inside the last scan (of %s); run 'sweep scan %s' first", path, root, path)
	}
	for _, f := range s.Findings {
		lf := strings.ToLower(f.Path)
		if f.IsDir && strings.HasPrefix(lp, lf+"/") {
			return fmt.Errorf("%s is inside %s, a single %s finding (rule %s) whose contents were not kept. Try 'sweep explain %s'",
				path, f.Path, f.Tier, f.RuleID, path)
		}
	}
	return fmt.Errorf("%s is under 1 MB or is a file; the saved scan keeps folders of 1 MB or more", path)
}

func renderLs(w io.Writer, o *lsOutput, home string) {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	fmt.Fprintf(w, "%s  %s\n", bold.Sprint(shortPath(o.Path, home)),
		faint.Sprintf("%s · %s files · scan from %s", report.Bytes(o.Size), report.Count(o.Files), report.Age(o.ScannedAt, time.Now())))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SIZE\tSHARE\tCLEANABLE\tTIER\tNAME")
	for _, r := range o.Rows {
		name := strings.Repeat("  ", r.Depth) + r.Name
		if r.IsDir {
			name += "/"
		}
		if r.Stale {
			name += "  (stale)"
		}
		tier := r.Tier
		if tier == "" {
			tier = "-"
		}
		cl := "-"
		if r.Cleanable > 0 {
			cl = report.Bytes(r.Cleanable)
		}
		share := float64(0)
		if o.Size > 0 {
			share = 100 * float64(r.Size) / float64(o.Size)
		}
		fmt.Fprintf(tw, "%s\t%.0f%%\t%s\t%s\t%s\n", report.Bytes(r.Size), share, cl, tier, name)
	}
	if o.OwnFiles > 0 {
		fmt.Fprintf(tw, "%s\t\t\t\t%s\n", report.Bytes(o.OwnFiles), faint.Sprint("(files directly here, and folders under 1 MB)"))
	}
	_ = tw.Flush()
	if o.Hidden > 0 {
		fmt.Fprintf(w, "%s\n", faint.Sprintf("… %d smaller entries (-n to show more)", o.Hidden))
	}

	fmt.Fprintln(w)
	var parts []string
	for _, t := range []safety.Tier{safety.TierSafe, safety.TierCaution, safety.TierReview, safety.TierProtected} {
		if c, ok := o.Cleanable[t.String()]; ok && c.Count > 0 {
			parts = append(parts, fmt.Sprintf("%s %s (%d)", report.TierLabel(t), report.Bytes(c.Size), c.Count))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintln(w, "No findings in this folder.")
		return
	}
	fmt.Fprintf(w, "Findings here: %s\n", strings.Join(parts, " · "))
	if c := o.Cleanable[safety.TierSafe.String()]; c.Count > 0 || o.Cleanable[safety.TierCaution.String()].Count > 0 {
		fmt.Fprintf(w, "Preview a cleanup of just this folder: %s\n", bold.Sprintf("sweep clean --under %s", shellQuote(shortPath(o.Path, home))))
	}
}
