// Package cli defines sweep's cobra commands.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// globalOptions are the flags shared by every command.
type globalOptions struct {
	JSON       bool
	NoColor    bool
	Verbose    bool
	ConfigPath string
}

// NewRootCmd builds the command tree. Output goes to the writers set on the
// returned command (cmd.OutOrStdout / cmd.ErrOrStderr) so tests can capture it.
func NewRootCmd(version string) *cobra.Command {
	return newRootCmd(version, defaultDoctorDeps())
}

func newRootCmd(version string, doctor doctorDeps) *cobra.Command {
	opts := &globalOptions{}
	root := &cobra.Command{
		Use:   "sweep",
		Short: "macOS disk analyzer and safe cleaner",
		Long: "sweep scans your disk, explains where the space goes (including macOS \"System Data\"),\n" +
			"classifies findings by safety, and cleans only what you approve.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			if opts.NoColor {
				color.NoColor = true
			}
		},
	}
	pf := root.PersistentFlags()
	pf.BoolVar(&opts.JSON, "json", false, "emit machine-readable JSON")
	pf.BoolVar(&opts.NoColor, "no-color", false, "disable colored output (also honors NO_COLOR)")
	pf.BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")
	pf.StringVar(&opts.ConfigPath, "config", "", "user rules file (default ~/.config/sweep/rules.yaml)")

	root.AddCommand(
		newDoctorCmd(opts, doctor),
		newScanCmd(opts),
		newReportCmd(opts),
		newTopCmd(opts),
		newLsCmd(opts),
		newExplainCmd(opts),
		newCleanCmd(opts),
		newRestoreCmd(opts),
		newRulesCmd(opts),
	)
	return root
}

// homeDir resolves the home directory from $HOME, so tests (and sandbox
// demos) redirect every path sweep writes by setting HOME.
func homeDir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return h, nil
}

// expandHome expands a leading ~ in a user-supplied path.
func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// shortPath abbreviates the home directory to ~ for display.
func shortPath(p, home string) string {
	if home == "" || home == "/" {
		return p
	}
	if p == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(p, home+"/"); ok {
		return "~/" + rest
	}
	return p
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Execute runs sweep and returns the process exit code.
func Execute(ctx context.Context, version string) int {
	return run(ctx, NewRootCmd(version), os.Stderr)
}

func run(ctx context.Context, cmd *cobra.Command, stderr io.Writer) int {
	err := cmd.ExecuteContext(ctx)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled) || ctx.Err() != nil:
		fmt.Fprintln(stderr, "sweep: interrupted")
		return 130
	default:
		fmt.Fprintf(stderr, "sweep: %v\n", err)
		return 1
	}
}
