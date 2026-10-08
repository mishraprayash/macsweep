package cli

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
)

// ruleFound is what one rule matched in the last scan.
type ruleFound struct {
	Items int    `json:"items"`
	Size  uint64 `json:"size_bytes"`
}

type ruleRow struct {
	*rules.Rule
	Found *ruleFound `json:"found,omitempty"`
}

func newRulesCmd(opts *globalOptions) *cobra.Command {
	var lf listFilter
	list := func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			lf.search = strings.Join(args, " ")
		}
		return runRulesList(cmd, opts, lf)
	}
	cmd := &cobra.Command{
		Use:   "rules [search]",
		Short: "Show what sweep recognizes: every rule, where it looks, and what it found",
		Long: "rules lists the built-in rules (and yours from ~/.config/sweep/rules.yaml): what each\n" +
			"one matches, its risk tier, and how much it found in the last scan.\n\n" +
			"  sweep rules                      all rules, grouped by category\n" +
			"  sweep rules chrome               rules mentioning \"chrome\"\n" +
			"  sweep rules --found              only rules that found something\n" +
			"  sweep rules --tier safe          only SAFE rules\n" +
			"  sweep rules show node-modules    one rule in detail, with its largest findings",
		Args: cobra.ArbitraryArgs,
		RunE: list,
	}
	listCmd := &cobra.Command{
		Use:   "list [search]",
		Short: "List rules (same as 'sweep rules')",
		Args:  cobra.ArbitraryArgs,
		RunE:  list,
	}
	for _, c := range []*cobra.Command{cmd, listCmd} {
		f := c.Flags()
		f.StringVar(&lf.category, "category", "", "only rules whose category contains this text")
		f.StringVar(&lf.tier, "tier", "", "only rules of this tier (safe, caution, review, protected)")
		f.BoolVar(&lf.found, "found", false, "only rules that found something in the last scan")
	}
	cmd.AddCommand(listCmd)

	var limit int
	show := &cobra.Command{
		Use:   "show <rule-id>",
		Short: "Show one rule in detail, with what it found in the last scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			eng, err := loadEngine(opts, home)
			if err != nil {
				return err
			}
			r, ok := eng.set.ByID(args[0])
			if !ok {
				return fmt.Errorf("no rule %q; see 'sweep rules %s'", args[0], args[0])
			}
			saved := loadSavedQuiet(home)
			var fs []classifier.Finding
			if saved != nil {
				for _, f := range saved.Findings {
					if f.RuleID == r.ID {
						fs = append(fs, f)
					}
				}
			}
			if opts.JSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					*rules.Rule
					Findings []classifier.Finding `json:"findings"`
				}{r, fs})
			}
			renderRule(cmd.OutOrStdout(), r, saved, fs, home, limit)
			return nil
		},
	}
	show.Flags().IntVarP(&limit, "limit", "n", 10, "number of findings to show")
	cmd.AddCommand(show)
	return cmd
}

type listFilter struct {
	search, category, tier string
	found                  bool
}

func runRulesList(cmd *cobra.Command, opts *globalOptions, lf listFilter) error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	eng, err := loadEngine(opts, home)
	if err != nil {
		return err
	}
	var tier safety.Tier
	if lf.tier != "" {
		if tier, err = safety.ParseTier(lf.tier); err != nil {
			return err
		}
	}
	saved := loadSavedQuiet(home)
	found := foundByRule(saved)
	if lf.found && saved == nil {
		return errors.New("--found needs a saved scan; run 'sweep scan' first")
	}

	var rows []ruleRow
	for _, r := range eng.set.Rules() {
		if tier != safety.TierUnknown && r.Tier != tier {
			continue
		}
		if lf.category != "" && !containsFold(r.Category, lf.category) {
			continue
		}
		if lf.search != "" && !containsFold(r.ID+" "+r.Category+" "+r.Description+" "+describeMatch(r), lf.search) {
			continue
		}
		row := ruleRow{Rule: r, Found: found[r.ID]}
		if lf.found && row.Found == nil {
			continue
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].ID < rows[j].ID
	})
	if opts.JSON {
		return writeJSON(cmd.OutOrStdout(), rows)
	}
	return renderRules(cmd.OutOrStdout(), rows, eng, saved, opts.Verbose, lf != listFilter{})
}

// loadSavedQuiet returns the saved scan, or nil if there is none or it
// cannot be read (rules work without one).
func loadSavedQuiet(home string) *cache.Scan {
	saved, err := cache.Load(cache.DefaultPath(home))
	if err != nil {
		return nil
	}
	return saved
}

func foundByRule(saved *cache.Scan) map[string]*ruleFound {
	out := map[string]*ruleFound{}
	if saved == nil {
		return out
	}
	for _, f := range saved.Findings {
		rf := out[f.RuleID]
		if rf == nil {
			rf = &ruleFound{}
			out[f.RuleID] = rf
		}
		rf.Items++
		rf.Size += f.Size
	}
	return out
}

func renderRules(w io.Writer, rows []ruleRow, eng *engine, saved *cache.Scan, verbose, filtered bool) error {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	user, cat := 0, ""
	var total uint64
	for _, r := range rows {
		if r.Category != cat {
			if cat != "" {
				fmt.Fprintln(tw, "\t\t\t")
			}
			cat = r.Category
			fmt.Fprintf(tw, "%s\t\t\t\n", bold.Sprint(cat))
		}
		id := r.ID
		if r.User {
			id += " (user)"
			user++
		}
		found := faint.Sprint("-")
		if saved == nil {
			found = ""
		} else if r.Found != nil {
			found = fmt.Sprintf("%s (%d)", report.Bytes(r.Found.Size), r.Found.Items)
			total += r.Found.Size
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", id, report.TierLabel(r.Tier), found, describeMatch(r.Rule))
		if verbose {
			fmt.Fprintf(tw, "  \t\t\t%s\n", faint.Sprint(r.Description))
			if len(r.NativeClean) > 0 {
				fmt.Fprintf(tw, "  \t\t\t%s\n", faint.Sprint("cleans with: "+strings.Join(r.NativeClean, " ")))
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "No rules match.")
		return nil
	}
	all := len(eng.set.Rules())
	if filtered {
		fmt.Fprintf(w, "\n%d of %d rules shown.", len(rows), all)
	} else {
		fmt.Fprintf(w, "\n%d rules (%d built-in, %d from %s).", len(rows), len(rows)-user, user, shortPath(eng.configPath, eng.home))
	}
	if saved != nil {
		fmt.Fprintf(w, " Found %s in the last scan of %s.", report.Bytes(total), shortPath(saved.Result.Root, eng.home))
	} else {
		fmt.Fprint(w, " Run 'sweep scan' to see what each rule finds.")
	}
	fmt.Fprintln(w)
	hint := "Details: sweep rules show <id>"
	if !verbose {
		hint += " · descriptions: --verbose"
	}
	fmt.Fprintln(w, faint.Sprint(hint))
	return nil
}

func renderRule(w io.Writer, r *rules.Rule, saved *cache.Scan, fs []classifier.Finding, home string, limit int) {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	fmt.Fprintln(w, bold.Sprint(r.ID))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "  %s\t%s\n", k, v)
		}
	}
	row("Category", r.Category)
	row("Tier", report.TierLabel(r.Tier)+"  "+tierMeaning(r.Tier))
	row("What", r.Description)
	row("Matches", describeMatch(r))
	if r.Synthetic {
		row("", "decided by sweep's built-in detector, which keeps the version in use")
	}
	row("Regenerate", r.RegenerateHint)
	if len(r.NativeClean) > 0 {
		how := "cleaned by running `" + strings.Join(r.NativeClean, " ") + "`"
		if r.NativeOnly {
			how += "; sweep never deletes these files itself"
		}
		row("Clean", how)
	} else if r.CleanContents {
		row("Clean", "emptied: its contents are removed, the folder stays")
	}
	if r.StaleAfterDays > 0 {
		row("Stale", fmt.Sprintf("flagged when the project has had no activity for %d days (clean --stale)", r.StaleAfterDays))
	}
	row("Source", r.Source)
	_ = tw.Flush()

	fmt.Fprintln(w)
	switch {
	case saved == nil:
		fmt.Fprintln(w, "No saved scan: run 'sweep scan' to see what this rule finds.")
		return
	case len(fs) == 0:
		fmt.Fprintf(w, "Found nothing in the last scan of %s.\n", shortPath(saved.Result.Root, home))
		return
	}
	var total uint64
	for _, f := range fs {
		total += f.Size
	}
	fmt.Fprintf(w, "%s in the last scan of %s: %s in %d items\n", bold.Sprint("Found"), shortPath(saved.Result.Root, home), report.Bytes(total), len(fs))
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Size > fs[j].Size })
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, f := range fs {
		if limit > 0 && i == limit {
			break
		}
		note := ""
		if f.Tier != r.Tier {
			note = faint.Sprintf("  (%s: %s)", report.TierLabel(f.Tier), f.Override)
		}
		fmt.Fprintf(tw, "  %s\t%s%s\n", report.Bytes(f.Size), shortPath(f.Path, home), note)
	}
	_ = tw.Flush()
	if limit > 0 && len(fs) > limit {
		fmt.Fprintln(w, faint.Sprintf("  … %d more (-n 0 shows all)", len(fs)-limit))
	}
	if r.Tier.Deletable() {
		flag := ""
		if r.Tier == safety.TierCaution {
			flag = " --tier caution"
		}
		fmt.Fprintln(w, faint.Sprintf("\nPreview a cleanup of just this rule: sweep clean --rule %s%s", r.ID, flag))
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// describeMatch summarises a rule's match conditions in one line.
func describeMatch(r *rules.Rule) string {
	m := r.Match
	var parts []string
	switch {
	case len(m.Path) > 0:
		parts = append(parts, strings.Join(m.Path, ", "))
	case len(m.Glob) > 0:
		parts = append(parts, strings.Join(m.Glob, ", "))
	case len(m.DirName) > 0:
		parts = append(parts, "dir "+strings.Join(m.DirName, " | "))
	case len(m.Name) > 0:
		parts = append(parts, "name "+strings.Join(m.Name, " | "))
	case len(m.Ext) > 0:
		parts = append(parts, "*"+strings.Join(m.Ext, " *"))
	}
	if m.Type != "" && len(m.DirName) == 0 {
		parts = append(parts, m.Type+"s only")
	}
	if len(m.RequireSiblingAny) > 0 {
		parts = append(parts, "next to "+strings.Join(m.RequireSiblingAny, "/"))
	}
	if len(m.RequireParentMarker) > 0 {
		parts = append(parts, "inside a dir with "+strings.Join(m.RequireParentMarker, "/"))
	}
	if len(m.RequireChildAny) > 0 {
		parts = append(parts, "containing "+strings.Join(m.RequireChildAny, "/"))
	}
	if m.Under != "" {
		parts = append(parts, "under "+m.Under)
	}
	if m.Project {
		parts = append(parts, "in your own folders")
	}
	if m.MinSize > 0 {
		parts = append(parts, fmt.Sprintf("≥ %d MB", uint64(m.MinSize)/1_000_000))
	}
	if m.MinAgeDays > 0 {
		parts = append(parts, fmt.Sprintf("older than %dd", m.MinAgeDays))
	}
	return strings.Join(parts, "; ")
}
