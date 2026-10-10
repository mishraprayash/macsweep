package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mishraprayash/macsweep/internal/audit"
	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/cleaner"
	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// Plans above either limit need the total size (or DELETE) typed back.
// Variables only so tests can lower them.
var (
	largePlanBytes uint64 = 50_000_000_000
	largePlanItems        = 500
)

// Overridable in tests so they never run real tools or depend on what is
// installed on the machine.
var (
	newRunner   = func() cleaner.Runner { return cleaner.ExecRunner{} }
	lookPath    = exec.LookPath
	runningApps = func(ctx context.Context) map[string]bool {
		apps, _ := macos.RunningApps(ctx) // best effort: no list, no warnings
		return apps
	}
	openFiles = macos.ListOpenFiles
)

type cleanFlags struct {
	tier        string
	categories  []string
	rules       []string
	names       []string
	under       []string
	excludes    []string
	olderThan   string
	minSize     string
	stale       bool
	dryRun      bool
	execute     bool
	yes         bool
	permanent   bool
	interactive bool
	skipNative  bool
	snapshots   bool
}

func newCleanCmd(opts *globalOptions) *cobra.Command {
	f := &cleanFlags{}
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Plan and (with --execute) carry out a cleanup from the last scan",
		Long: `clean builds a deletion plan from the last scan (scanning your home folder first
if there is none) and shows it. Nothing is
changed unless you pass --execute, and even then you are asked to confirm.

Only SAFE items are included by default; add --tier caution for CAUTION items.
REVIEW and PROTECTED items are never cleaned. Items go to the Trash unless you
pass --permanent. Every action is recorded in ~/Library/Logs/sweep/history.jsonl.

Narrow the plan with filters (all must match):
  sweep clean --name node_modules --name .next      only these folder names
  sweep clean --under ~/code/old-project            only inside one folder
  sweep clean --category "Dev: JavaScript"          one category (see 'sweep rules list')
  sweep clean --rule rust-target --stale            stale Rust build output only
  sweep clean --older-than 90d --min-size 500MB     big, long-untouched items
  sweep clean --exclude "~/code/keep/**"            leave a folder alone
  sweep clean --interactive                         pick items one by one
  sweep clean --snapshots --interactive             also thin Time Machine local snapshots

Inspect first with 'sweep show', 'sweep show <folder>', or 'sweep show <path>'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClean(cmd, opts, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.tier, "tier", "safe", "highest tier to include: safe or caution")
	fl.StringArrayVar(&f.categories, "category", nil, "only this category (repeatable)")
	fl.StringArrayVar(&f.rules, "rule", nil, "only this rule id (repeatable)")
	fl.StringArrayVar(&f.names, "name", nil, "only items with this file/folder name, globs allowed (repeatable)")
	fl.StringArrayVar(&f.under, "under", nil, "only items inside this folder (repeatable)")
	fl.StringArrayVar(&f.excludes, "exclude", nil, "leave paths matching this glob alone (repeatable)")
	fl.StringVar(&f.olderThan, "older-than", "", "only items untouched for this long, e.g. 30d, 12w, 6m, 1y")
	fl.StringVar(&f.minSize, "min-size", "", "only items at least this big, e.g. 100MB")
	fl.BoolVar(&f.stale, "stale", false, "only artifacts of stale projects")
	fl.BoolVar(&f.dryRun, "dry-run", true, "show the plan without changing anything (the default)")
	fl.BoolVar(&f.execute, "execute", false, "carry out the plan (asks for confirmation)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "with --execute: do not ask y/N (large plans still require typing)")
	fl.BoolVar(&f.permanent, "permanent", false, "delete instead of moving to the Trash (cannot be undone)")
	fl.BoolVarP(&f.interactive, "interactive", "i", false, "choose items one by one before confirming")
	fl.BoolVar(&f.skipNative, "skip-native", false, "never run native cleanup commands (go clean, brew cleanup, ...)")
	fl.BoolVar(&f.snapshots, "snapshots", false, "also ask macOS to thin local Time Machine snapshots (tmutil)")
	return cmd
}

// plannedOpenFiles is best effort: the plan just shows fewer warnings without
// it. Execution reads the list again and refuses to clean if it cannot.
func plannedOpenFiles(ctx context.Context) *macos.OpenFiles {
	open, _ := openFiles(ctx)
	return open
}

func runClean(cmd *cobra.Command, opts *globalOptions, f *cleanFlags) error {
	if f.execute && cmd.Flags().Changed("dry-run") && f.dryRun {
		return errors.New("--dry-run and --execute contradict each other; pick one")
	}
	sel, err := f.selector()
	if err != nil {
		return err
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	eng, err := loadEngine(opts, home)
	if err != nil {
		return err
	}
	saved, err := cache.Load(cache.DefaultPath(home))
	if errors.Is(err, cache.ErrNoScan) {
		fmt.Fprintln(cmd.ErrOrStderr(), "No saved scan yet; scanning your home folder first.")
		saved, _, err = scanAndSave(cmd.Context(), cmd.ErrOrStderr(), opts, home, scanner.Options{Root: home})
	}
	if err != nil {
		return err
	}
	plan, err := cleaner.BuildPlan(saved, sel, eng.set, eng.guard, cleaner.Options{
		Permanent: f.permanent, SkipNative: f.skipNative, Now: eng.now(), LookPath: lookPath,
		RunningApps: runningApps(cmd.Context()), Snapshots: f.snapshots,
		OpenFiles: plannedOpenFiles(cmd.Context()),
	})
	if err != nil {
		return err
	}

	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	in := promptInput(cmd.InOrStdin())
	if f.interactive {
		if !stdinIsTerminal(cmd.InOrStdin()) {
			return errors.New("--interactive needs a terminal")
		}
		if err := pickItems(in, errOut, plan, home); err != nil {
			return err
		}
	}

	if !f.execute {
		if opts.JSON {
			return writeJSON(out, plan)
		}
		renderPlan(out, plan, home, true, opts.Verbose)
		fmt.Fprintf(out, "\n%s\n", color.New(color.Bold).Sprint("Dry run: nothing was changed."))
		if len(plan.Items) > 0 {
			fmt.Fprintf(out, "To clean these items, run:\n  %s --execute\n", commandLine(cmd))
		}
		return nil
	}

	if !opts.JSON {
		renderPlan(out, plan, home, false, opts.Verbose)
	}
	if len(plan.Items) == 0 {
		if opts.JSON {
			return writeJSON(out, map[string]any{"plan": plan, "summary": nil})
		}
		fmt.Fprintln(out, "\nNothing to clean.")
		return nil
	}
	if err := confirm(cmd.InOrStdin(), in, errOut, plan, f.yes); err != nil {
		return err
	}

	log, err := audit.Open(audit.DefaultPath(home), nil)
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	ex := &cleaner.Executor{
		Guard: eng.guard, Rules: eng.set, TrashDir: filepath.Join(home, ".Trash"),
		Audit: log, Runner: newRunner(), Out: out,
		OpenFiles: func() (*macos.OpenFiles, error) { return openFiles(cmd.Context()) },
	}
	if opts.JSON {
		ex.Out = errOut
	}
	fmt.Fprintln(ex.Out)
	sum := ex.Execute(cmd.Context(), plan)

	if err := forgetCleaned(home, saved, sum); err != nil {
		fmt.Fprintf(errOut, "warning: could not update the saved scan: %v\n", err)
	}
	if opts.JSON {
		return writeJSON(out, map[string]any{"plan": plan, "summary": sum})
	}
	renderSummary(out, sum, home)
	if sum.Interrupted {
		return context.Canceled
	}
	if sum.Failed > 0 {
		return fmt.Errorf("%d items failed; see above and the audit log", sum.Failed)
	}
	return nil
}

func (f *cleanFlags) selector() (cleaner.Selector, error) {
	sel := cleaner.Selector{
		Categories: f.categories, Rules: f.rules, Names: f.names, Under: f.under,
		Excludes: f.excludes, StaleOnly: f.stale,
	}
	switch strings.ToLower(f.tier) {
	case "safe":
		sel.MaxTier = safety.TierSafe
	case "caution":
		sel.MaxTier = safety.TierCaution
	case "review", "protected":
		return sel, fmt.Errorf("--tier %s: REVIEW and PROTECTED items are never cleaned; use safe or caution", f.tier)
	default:
		return sel, fmt.Errorf("--tier must be safe or caution, got %q", f.tier)
	}
	if f.olderThan != "" {
		d, err := parseAge(f.olderThan)
		if err != nil {
			return sel, err
		}
		sel.OlderThan = d
	}
	if f.minSize != "" {
		n, err := rules.ParseSize(f.minSize)
		if err != nil {
			return sel, fmt.Errorf("--min-size: %w", err)
		}
		sel.MinSize = uint64(n)
	}
	return sel, nil
}

var ageRE = regexp.MustCompile(`^(\d+)\s*([hdwmy])$`)

// parseAge parses durations like 36h, 30d, 12w, 6m (30-day months), 1y.
func parseAge(s string) (time.Duration, error) {
	m := ageRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("--older-than %q: use a number and unit, e.g. 30d, 12w, 6m, 1y", s)
	}
	n, _ := strconv.Atoi(m[1])
	day := 24 * time.Hour
	unit := map[string]time.Duration{"h": time.Hour, "d": day, "w": 7 * day, "m": 30 * day, "y": 365 * day}[m[2]]
	return time.Duration(n) * unit, nil
}

// commandLine reconstructs the clean invocation from the flags the user set,
// so the dry run can show exactly what to run next.
func commandLine(cmd *cobra.Command) string {
	parts := []string{"sweep clean"}
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		if fl.Name == "dry-run" || fl.Name == "execute" || fl.Name == "interactive" {
			return
		}
		if sv, ok := fl.Value.(pflag.SliceValue); ok {
			for _, v := range sv.GetSlice() {
				parts = append(parts, "--"+fl.Name+" "+shellQuote(v))
			}
			return
		}
		if fl.Value.Type() == "bool" {
			parts = append(parts, "--"+fl.Name)
			return
		}
		parts = append(parts, "--"+fl.Name+" "+shellQuote(fl.Value.String()))
	})
	for _, name := range []string{"config"} {
		if fl := cmd.Root().PersistentFlags().Lookup(name); fl != nil && fl.Changed {
			parts = append(parts, "--"+name+" "+shellQuote(fl.Value.String()))
		}
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`*?[]{}()<>|&;#!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func methodLabel(it cleaner.Item) string {
	switch {
	case it.Method == cleaner.MethodNative:
		return "run command"
	case it.Contents && it.Method == cleaner.MethodPermanent:
		return "empty (delete)"
	case it.Contents:
		return "empty (to Trash)"
	case it.Method == cleaner.MethodPermanent:
		return "delete"
	default:
		return "move to Trash"
	}
}

func renderPlan(w io.Writer, p *cleaner.Plan, home string, dryRun, verbose bool) {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	mode := "DRY RUN"
	if !dryRun {
		mode = "TO EXECUTE"
	}
	fmt.Fprintf(w, "%s %s  %s\n", bold.Sprint("Clean plan"),
		faint.Sprintf("· scan of %s · %s", shortPath(p.ScanRoot, home), report.Age(p.ScannedAt, time.Now())),
		color.New(color.FgCyan).Sprintf("[%s]", mode))
	if p.Permanent {
		fmt.Fprintln(w, color.New(color.FgRed, color.Bold).Sprint("--permanent: items will be deleted, not moved to the Trash. This cannot be undone."))
	}

	files := 0
	if len(p.Items) == 0 {
		fmt.Fprintln(w, "\nNothing selected.")
	} else {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  #\tSIZE\tTIER\tACTION\tPATH")
		shown := p.Items
		if !verbose && len(shown) > planRows+planSlack {
			shown = shown[:planRows]
		}
		for _, it := range p.Items {
			if it.Method != cleaner.MethodNative {
				files++
			}
		}
		for i, it := range shown {
			note := ""
			if it.Stale {
				note = "  (stale project)"
			}
			if it.Method == cleaner.MethodNative {
				note = "  $ " + strings.Join(it.Command, " ")
			}
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s%s\n", i+1, report.Bytes(it.Size), it.Tier, methodLabel(it), shortPath(it.Path, home), note)
		}
		_ = tw.Flush()
		renderRest(w, p.Items[len(shown):])
	}

	var fileBytes, nativeBytes uint64
	for _, it := range p.Items {
		if it.Method == cleaner.MethodNative {
			nativeBytes += it.Size
		} else {
			fileBytes += it.Size
		}
	}
	where := "moved to the Trash (recoverable until you empty it)"
	if p.Permanent {
		where = "deleted permanently"
	}
	fmt.Fprintf(w, "\nTotal: %s in %d items %s", report.Bytes(fileBytes), files, where)
	if groups := p.NativeGroups(); len(groups) > 0 {
		fmt.Fprintf(w, "; plus %d native command(s) covering %s", len(groups), report.Bytes(nativeBytes))
	}
	fmt.Fprintln(w, ".")

	if len(p.Left) > 0 || p.NeverCleaned > 0 || p.FilteredOut > 0 {
		fmt.Fprintln(w, "\nLeft out:")
		renderLeft(w, p.Left, home, verbose)
		if p.NeverCleaned > 0 {
			fmt.Fprintf(w, "  %d REVIEW/PROTECTED items (%s) are never cleaned; see 'sweep show'.\n", p.NeverCleaned, report.Bytes(p.NeverCleanedSize))
		}
		if p.FilteredOut > 0 {
			fmt.Fprintf(w, "  %d other findings did not match your filters.\n", p.FilteredOut)
		}
	}
}

// A plan longer than planRows+planSlack items lists only the planRows
// largest; the rest are summarized by category (--verbose lists them all).
const (
	planRows  = 20
	planSlack = 5
)

// renderRest summarizes the plan items not listed one by one.
func renderRest(w io.Writer, rest []cleaner.Item) {
	if len(rest) == 0 {
		return
	}
	type group struct {
		name  string
		n     int
		bytes uint64
	}
	var total uint64
	idx := map[string]int{}
	var groups []group
	for _, it := range rest {
		total += it.Size
		i, ok := idx[it.Category]
		if !ok {
			i = len(groups)
			idx[it.Category] = i
			groups = append(groups, group{name: it.Category})
		}
		groups[i].n++
		groups[i].bytes += it.Size
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].bytes > groups[j].bytes })
	fmt.Fprintf(w, "  … and %d smaller items (%s):\n", len(rest), report.Bytes(total))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, g := range groups {
		if i == planSlack {
			var n int
			var b uint64
			for _, o := range groups[i:] {
				n, b = n+o.n, b+o.bytes
			}
			fmt.Fprintf(tw, "      %s\t%s\t%s\n", "other categories", itemsCount(n), report.Bytes(b))
			break
		}
		fmt.Fprintf(tw, "      %s\t%s\t%s\n", g.name, itemsCount(g.n), report.Bytes(g.bytes))
	}
	_ = tw.Flush()
	fmt.Fprintln(w, color.New(color.Faint).Sprint("  --verbose lists every item; --interactive lets you pick."))
}

func itemsCount(n int) string {
	if n == 1 {
		return "1 item"
	}
	return fmt.Sprintf("%d items", n)
}

// confirm asks before executing. Large plans always need the total typed
// back, even with --yes; without a terminal they are refused.
func confirm(raw io.Reader, in *bufio.Reader, errOut io.Writer, p *cleaner.Plan, yes bool) error {
	total := p.Total()
	large := total > largePlanBytes || len(p.Items) > largePlanItems
	interactive := stdinIsTerminal(raw)
	if large {
		if !interactive {
			return fmt.Errorf("this plan is large (%s, %d items); run it from a terminal to confirm, or narrow it with filters", report.Bytes(total), len(p.Items))
		}
		want := report.Bytes(total)
		fmt.Fprintf(errOut, "\nThis plan is large (%s, %d items). Type %q or DELETE to continue: ", want, len(p.Items), want)
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != want && line != "DELETE" {
			return errors.New("not confirmed; nothing was changed")
		}
		return nil
	}
	if yes {
		return nil
	}
	if !interactive {
		return errors.New("refusing to clean without confirmation: run from a terminal or pass --yes")
	}
	verb := "Move %d items (%s) to the Trash"
	if p.Permanent {
		verb = "PERMANENTLY delete %d items (%s)"
	}
	q := fmt.Sprintf(verb, len(p.Items), report.Bytes(total))
	if n := len(p.NativeGroups()); n > 0 {
		q += fmt.Sprintf(" and run %d command(s)", n)
	}
	fmt.Fprintf(errOut, "\n%s? [y/N] ", q)
	line, _ := in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return errors.New("not confirmed; nothing was changed")
	}
}

// pickItems lets the user toggle plan items by number before confirming.
func pickItems(in *bufio.Reader, w io.Writer, p *cleaner.Plan, home string) error {
	if len(p.Items) == 0 {
		return nil
	}
	selected := make([]bool, len(p.Items))
	for i := range selected {
		selected[i] = true
	}
	for {
		fmt.Fprintln(w)
		var total uint64
		for i, it := range p.Items {
			box := "[ ]"
			if selected[i] {
				box = "[x]"
				total += it.Size
			}
			fmt.Fprintf(w, "  %s %3d. %9s  %-9s %s\n", box, i+1, report.Bytes(it.Size), it.Tier, shortPath(it.Path, home))
		}
		fmt.Fprintf(w, "Selected: %s. Toggle with numbers or ranges (1 3-5), a = all, n = none, Enter = done, q = quit: ", report.Bytes(total))
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		switch line {
		case "q":
			return errors.New("cancelled; nothing was changed")
		case "a":
			for i := range selected {
				selected[i] = true
			}
			continue
		case "n":
			for i := range selected {
				selected[i] = false
			}
			continue
		}
		if perr := toggle(selected, line); perr != nil {
			fmt.Fprintf(w, "  %v\n", perr)
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	kept := p.Items[:0]
	for i, it := range p.Items {
		if selected[i] {
			kept = append(kept, it)
		}
	}
	p.Items = kept
	return nil
}

func toggle(selected []bool, spec string) error {
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool { return r == ' ' || r == ',' }) {
		lo, hi, isRange := strings.Cut(tok, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a < 1 || b > len(selected) || a > b {
			return fmt.Errorf("%q is not a valid item number or range (1-%d)", tok, len(selected))
		}
		for i := a; i <= b; i++ {
			selected[i-1] = !selected[i-1]
		}
	}
	return nil
}

func renderSummary(w io.Writer, s *cleaner.Summary, home string) {
	bold := color.New(color.Bold)
	fmt.Fprintf(w, "\n%s %d moved to the Trash, %d deleted (%s freed); %d native command(s) run; %d skipped; %d failed.\n",
		bold.Sprint("Done:"), s.Trashed, s.Deleted, report.Bytes(s.Freed), s.NativeRuns, s.Skipped, s.Failed)
	if s.Interrupted {
		fmt.Fprintln(w, color.New(color.FgYellow).Sprint("Interrupted: the remaining items were not touched."))
	}
	if s.Trashed > 0 {
		fmt.Fprintln(w, "Trashed items can be restored from the Trash in Finder until you empty it (original paths are in the audit log).")
	}
	if s.Skipped > 0 {
		fmt.Fprintln(w, "Skipped items changed since the scan or failed a safety check; reasons are listed above.")
	}
	fmt.Fprintf(w, "Audit log: %s\n", shortPath(s.AuditLog, home))
	if len(s.Cleaned) > 0 {
		fmt.Fprintln(w, "Cleaned items were removed from the saved scan; run 'sweep scan' for fresh totals.")
	}
}

// forgetCleaned drops cleaned findings from the saved scan so a later
// report or clean does not offer them again.
func forgetCleaned(home string, s *cache.Scan, sum *cleaner.Summary) error {
	if len(sum.Cleaned) == 0 {
		return nil
	}
	done := map[string]bool{}
	for _, p := range sum.Cleaned {
		done[p] = true
	}
	if done["Time Machine local snapshots"] {
		s.Snapshots = nil
	}
	kept := s.Findings[:0]
	for _, f := range s.Findings {
		if done[f.Path] {
			s.CleanedBytes += f.Size
			s.CleanedItems++
			continue
		}
		kept = append(kept, f)
	}
	s.Findings = kept
	return cache.Save(cache.DefaultPath(home), s)
}

// leftPerReason is how many left-out items are listed per reason before the
// rest are summarised (all with --verbose).
const leftPerReason = 3

// renderLeft lists left-out items grouped by reason, largest group first,
// so hundreds of small CAUTION caches do not bury the useful lines.
func renderLeft(w io.Writer, left []cleaner.Left, home string, verbose bool) {
	faint := color.New(color.Faint)
	type group struct {
		reason string
		items  []cleaner.Left
		size   uint64
	}
	var groups []*group
	byReason := map[string]*group{}
	for _, l := range left {
		g := byReason[l.Reason]
		if g == nil {
			g = &group{reason: l.Reason}
			byReason[l.Reason] = g
			groups = append(groups, g)
		}
		g.items = append(g.items, l)
		g.size += l.Size
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].size > groups[j].size })
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, g := range groups {
		sort.SliceStable(g.items, func(i, j int) bool { return g.items[i].Size > g.items[j].Size })
		shown := g.items
		if !verbose && len(shown) > leftPerReason {
			shown = shown[:leftPerReason]
		}
		for _, l := range shown {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", report.Bytes(l.Size), shortPath(l.Path, home), faint.Sprint(l.Reason))
		}
		if rest := g.items[len(shown):]; len(rest) > 0 {
			var size uint64
			for _, l := range rest {
				size += l.Size
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", report.Bytes(size), faint.Sprintf("… %d more like this (--verbose lists them)", len(rest)), faint.Sprint(g.reason))
		}
	}
	_ = tw.Flush()
}
