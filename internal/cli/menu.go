package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/cache"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
	"github.com/mishraprayash/macsweep/internal/scanner"
)

// menuRescanAfter: the menu scans the home folder first when the saved scan
// is missing or older than this.
const menuRescanAfter = time.Hour

// menuChoice is one entry of the menu. Each runs a command a user could
// also type, so the menu adds no behaviour of its own: the same dry run,
// confirmation, Trash and audit log apply.
type menuChoice struct {
	key   string
	label string
	args  []string // the command, without "sweep"
}

var menuChoices = []menuChoice{
	{"1", "See what is using space", []string{"show"}},
	{"2", "See the largest files and folders", []string{"show", "--largest", "-n", "15"}},
	{"3", "Clean up caches and build files (safe; asks first)", []string{"clean", "--execute"}},
	{"4", "Clean up more: pick from larger items that take longer to rebuild", []string{"clean", "--tier", "caution", "--interactive", "--execute"}},
	{"5", "Remove leftovers of apps you deleted (pick items)", []string{"clean", "--tier", "caution", "--rule", rules.LeftoverRuleID, "--interactive", "--execute"}},
	{"6", "Undo the last clean-up", []string{"restore", "--execute"}},
	{"7", "Scan again", []string{"scan", "~"}},
	{"8", "Check permissions (Full Disk Access)", []string{"doctor"}},
}

// wantsMenu reports whether 'sweep' was run by a person at a terminal. In
// scripts, plain 'sweep' scans the home folder instead.
func wantsMenu(cmd *cobra.Command, opts *globalOptions) bool {
	return !opts.JSON && stdinIsTerminal(cmd.InOrStdin()) && isTerminal(cmd.OutOrStdout())
}

// menu runs the interactive menu. newRoot builds a fresh command tree for
// each choice, so no flag values carry over from one choice to the next.
type menu struct {
	ctx         context.Context
	opts        *globalOptions
	home        string
	in          terminalInput
	out, errOut io.Writer
	newRoot     func() *cobra.Command
}

func runMenu(cmd *cobra.Command, opts *globalOptions, newRoot func() *cobra.Command) error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	m := &menu{
		ctx: cmd.Context(), opts: opts, home: home,
		in:  terminalInput{bufio.NewReader(cmd.InOrStdin())},
		out: cmd.OutOrStdout(), errOut: cmd.ErrOrStderr(), newRoot: newRoot,
	}
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	fmt.Fprintln(m.out, bold.Sprint("sweep")+faint.Sprint(" · find what fills your Mac and clean it safely"))
	if err := m.freshScan(); err != nil {
		return err
	}
	for {
		m.header()
		for _, c := range menuChoices {
			fmt.Fprintf(m.out, "  %s  %s\n", bold.Sprint(c.key), c.label)
		}
		fmt.Fprintf(m.out, "  %s  Quit\n\nChoose a number: ", bold.Sprint("q"))
		answer, err := m.in.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		switch {
		case m.ctx.Err() != nil:
			return m.ctx.Err() // Ctrl-C
		case (err != nil && answer == "") || answer == "q" || answer == "quit" || answer == "exit":
			fmt.Fprintln(m.out)
			return nil
		case answer == "":
			continue // just Enter: show the menu again
		}
		choice, ok := findChoice(answer)
		if !ok {
			fmt.Fprintf(m.out, "\n%q is not on the menu; type a number from 1 to %d, or q to quit.\n", answer, len(menuChoices))
			continue
		}
		fmt.Fprintf(m.out, "\n%s\n\n", faint.Sprintf("(same as typing: sweep %s)", strings.Join(choice.args, " ")))
		if err := m.run(choice.args...); err != nil {
			if m.ctx.Err() != nil {
				return err
			}
			fmt.Fprintf(m.errOut, "\n%v\n", err)
		}
		fmt.Fprint(m.out, faint.Sprint("\nPress Enter to go back to the menu. "))
		if _, err := m.in.ReadString('\n'); err != nil {
			fmt.Fprintln(m.out)
			return m.ctx.Err() // nil at the end of input; set after Ctrl-C
		}
		fmt.Fprintln(m.out)
	}
}

func findChoice(key string) (menuChoice, bool) {
	for _, c := range menuChoices {
		if c.key == key {
			return c, true
		}
	}
	return menuChoice{}, false
}

// run executes one command, with the menu's input and output and the same
// global flags sweep was started with.
func (m *menu) run(args ...string) error {
	c := m.newRoot()
	if m.opts.ConfigPath != "" {
		args = append(args, "--config", m.opts.ConfigPath)
	}
	if m.opts.NoColor {
		args = append(args, "--no-color")
	}
	if m.opts.Verbose {
		args = append(args, "--verbose")
	}
	c.SetArgs(args)
	c.SetIn(m.in)
	c.SetOut(m.out)
	c.SetErr(m.errOut)
	return c.ExecuteContext(m.ctx)
}

// freshScan scans the home folder when there is no recent saved scan, so the
// menu's numbers are current.
func (m *menu) freshScan() error {
	saved, err := cache.Load(cache.DefaultPath(m.home))
	if err == nil && time.Since(saved.Result.FinishedAt) < menuRescanAfter {
		return nil
	}
	fmt.Fprintln(m.out, "\nLooking through your home folder (this only reads; nothing is changed)...")
	_, _, err = scanAndSave(m.ctx, m.errOut, m.opts, m.home, scanner.Options{Root: m.home})
	return err
}

// header summarizes the saved scan above the menu.
func (m *menu) header() {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	saved, err := cache.Load(cache.DefaultPath(m.home))
	if err != nil {
		fmt.Fprintln(m.out, "\nNo scan yet: choose 7 to scan your home folder.")
		return
	}
	fmt.Fprintln(m.out)
	if d := saved.Disk; d != nil {
		fmt.Fprintf(m.out, "Your disk: %s used, %s free\n", report.Bytes(d.Used), report.Bytes(d.Available))
	}
	totals := map[safety.Tier]report.TierTotal{}
	for _, t := range report.TierTotals(saved.Findings) {
		totals[t.Tier] = t
	}
	var leftovers uint64
	for _, f := range saved.Findings {
		if f.RuleID == rules.LeftoverRuleID {
			leftovers += f.Size
		}
	}
	line := "Safe to clean now: " + bold.Sprint(report.Bytes(totals[safety.TierSafe].Size))
	if more := totals[safety.TierCaution].Size; more > 0 {
		line += "   More you can choose to clean: " + report.Bytes(more)
		if leftovers > 0 {
			line += fmt.Sprintf(" (%s from deleted apps)", report.Bytes(leftovers))
		}
	}
	fmt.Fprintln(m.out, line)
	fmt.Fprintf(m.out, "%s\n\n", faint.Sprintf("Scan of %s, %s.", shortPath(saved.Result.Root, m.home), report.Age(saved.Result.FinishedAt, time.Now())))
}
