package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/audit"
	"github.com/mishraprayash/macsweep/internal/cleaner"
	"github.com/mishraprayash/macsweep/internal/report"
)

func newRestoreCmd(opts *globalOptions) *cobra.Command {
	var session string
	var list, execute, yes bool
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Move items that 'sweep clean' put in the Trash back where they were",
		Long: "restore reads the audit log and moves the items a clean session put in the Trash\n" +
			"back to their original locations. Finder's \"Put Back\" does not know about them.\n" +
			"It shows what it would do unless --execute is given, and never overwrites anything.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			logPath := audit.DefaultPath(home)
			order, items, err := cleaner.Sessions(logPath)
			if errors.Is(err, fs.ErrNotExist) {
				return errors.New("no audit log yet: nothing has been cleaned")
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if list {
				return renderSessions(out, order, items)
			}
			if session == "" {
				for i := len(order) - 1; i >= 0; i-- {
					if len(items[order[i]]) > 0 {
						session = order[i]
						break
					}
				}
				if session == "" {
					fmt.Fprintln(out, "Nothing to restore: no trashed items are left in the audit log.")
					return nil
				}
			}
			sel, ok := items[session]
			if !ok {
				return fmt.Errorf("unknown session %q; see 'sweep restore --list'", session)
			}
			cleaner.CheckRestore(sel, filepath.Join(home, ".Trash"))
			if opts.JSON && !execute {
				return writeJSON(out, sel)
			}
			renderRestorePlan(out, session, sel, home)
			if !execute {
				fmt.Fprintf(out, "\nDry run: nothing was moved. To restore, run:\n  sweep restore --session %s --execute\n", session)
				return nil
			}
			ready := 0
			for _, it := range sel {
				if it.Problem == "" {
					ready++
				}
			}
			if ready == 0 {
				return errors.New("nothing in this session can be restored")
			}
			if !yes {
				if !stdinIsTerminal(cmd.InOrStdin()) {
					return errors.New("refusing to restore without confirmation: run from a terminal or pass --yes")
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\nRestore %d items? [y/N] ", ready)
				line, _ := promptInput(cmd.InOrStdin()).ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
					return errors.New("not confirmed; nothing was moved")
				}
			}
			log, err := audit.Open(logPath, nil)
			if err != nil {
				return err
			}
			defer func() { _ = log.Close() }()
			done, failed := 0, 0
			for _, it := range sel {
				if it.Problem != "" {
					continue
				}
				if err := cleaner.Restore(it, log); err != nil {
					failed++
					fmt.Fprintf(out, "✗ %s  %v\n", shortPath(it.Path, home), err)
					continue
				}
				done++
				fmt.Fprintf(out, "✓ %s  restored\n", shortPath(it.Path, home))
			}
			fmt.Fprintf(out, "\nRestored %d, failed %d. Run 'sweep scan' to refresh totals.\n", done, failed)
			if failed > 0 {
				return fmt.Errorf("%d items could not be restored", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&session, "session", "", "session to restore (default: the most recent one)")
	cmd.Flags().BoolVar(&list, "list", false, "list clean sessions with restorable items")
	cmd.Flags().BoolVar(&execute, "execute", false, "move the items back (asks for confirmation)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "with --execute: do not ask for confirmation")
	return cmd
}

func renderSessions(w io.Writer, order []string, items map[string][]cleaner.RestoreItem) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tITEMS\tSIZE")
	n := 0
	for i := len(order) - 1; i >= 0; i-- {
		list := items[order[i]]
		if len(list) == 0 {
			continue
		}
		var size uint64
		for _, it := range list {
			size += it.Size
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\n", order[i], len(list), report.Bytes(size))
		n++
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintln(w, "No restorable sessions.")
	}
	return nil
}

func renderRestorePlan(w io.Writer, session string, items []cleaner.RestoreItem, home string) {
	fmt.Fprintf(w, "%s %s\n\n", color.New(color.Bold).Sprint("Restore"), color.New(color.Faint).Sprintf("· session %s", session))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SIZE\tTO\tSTATUS")
	for _, it := range items {
		status := "ready"
		if it.Problem != "" {
			status = "cannot restore: " + it.Problem
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", report.Bytes(it.Size), shortPath(it.Path, home), status)
	}
	_ = tw.Flush()
}
