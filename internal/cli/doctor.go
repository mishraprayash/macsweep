package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/mishraprayash/macsweep/internal/macos"
	"github.com/mishraprayash/macsweep/internal/report"
)

// doctorDeps isolates doctor from the real system so it can be tested.
type doctorDeps struct {
	home     func() (string, error)
	version  func(context.Context) (string, error)
	fda      func(home string) (macos.Access, string)
	volume   func() string
	statfs   func(string) (macos.DiskUsage, error)
	euid     func() int
	terminal func() string
}

func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		home:     os.UserHomeDir,
		version:  macos.ProductVersion,
		fda:      macos.FullDiskAccess,
		volume:   macos.SystemVolume,
		statfs:   macos.Statfs,
		euid:     os.Geteuid,
		terminal: macos.Terminal,
	}
}

type doctorReport struct {
	OS             string           `json:"os"`
	Arch           string           `json:"arch"`
	MacOSVersion   string           `json:"macos_version,omitempty"`
	Root           bool             `json:"running_as_root"`
	FullDiskAccess macos.Access     `json:"full_disk_access"`
	FDAProbe       string           `json:"full_disk_access_probe,omitempty"`
	Terminal       string           `json:"terminal"`
	Disk           *macos.DiskUsage `json:"disk,omitempty"`
	Warnings       []string         `json:"warnings"`
}

func newDoctorCmd(opts *globalOptions, deps doctorDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check permissions, macOS version, and disk totals",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := collectDoctor(cmd.Context(), deps)
			if err != nil {
				return err
			}
			if opts.JSON {
				return writeJSON(cmd.OutOrStdout(), r)
			}
			return renderDoctor(cmd.OutOrStdout(), r)
		},
	}
}

func collectDoctor(ctx context.Context, d doctorDeps) (doctorReport, error) {
	r := doctorReport{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Root:     d.euid() == 0,
		Terminal: d.terminal(),
		Warnings: []string{},
	}
	if runtime.GOOS != "darwin" {
		r.Warnings = append(r.Warnings, "sweep is built for macOS; results on other systems are not meaningful")
	}

	home, err := d.home()
	if err != nil {
		return r, fmt.Errorf("cannot determine home directory: %w", err)
	}

	if v, err := d.version(ctx); err != nil {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		r.Warnings = append(r.Warnings, fmt.Sprintf("could not read macOS version: %v", err))
	} else {
		r.MacOSVersion = v
	}

	r.FullDiskAccess, r.FDAProbe = d.fda(home)

	if du, err := d.statfs(d.volume()); err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("could not read disk totals: %v", err))
	} else {
		r.Disk = &du
	}
	return r, nil
}

func renderDoctor(w io.Writer, r doctorReport) error {
	green, yellow, red := color.New(color.FgGreen), color.New(color.FgYellow), color.New(color.FgRed)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	version := r.MacOSVersion
	if version == "" {
		version = "unknown"
	}
	fmt.Fprintf(tw, "macOS\t%s (%s)\n", version, r.Arch)

	if r.Root {
		fmt.Fprintf(tw, "Running as\t%s\n", yellow.Sprint("root (not required; prefer running as yourself)"))
	} else {
		fmt.Fprintf(tw, "Running as\tuser (no sudo needed)\n")
	}

	switch r.FullDiskAccess {
	case macos.AccessGranted:
		fmt.Fprintf(tw, "Full Disk Access\t%s\n", green.Sprint("✓ granted"))
	case macos.AccessDenied:
		fmt.Fprintf(tw, "Full Disk Access\t%s\n", red.Sprint("✗ not granted"))
	default:
		fmt.Fprintf(tw, "Full Disk Access\t%s\n", yellow.Sprint("? could not determine"))
	}

	if r.Disk != nil {
		fmt.Fprintf(tw, "Disk (%s)\t%s total · %s used · %s available\n",
			r.Disk.Path, report.Bytes(r.Disk.Total), report.Bytes(r.Disk.Used), report.Bytes(r.Disk.Available))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "%s %s\n", yellow.Sprint("warning:"), warn)
	}

	if r.FullDiskAccess != macos.AccessGranted {
		fmt.Fprintf(w, `
Without Full Disk Access, parts of ~/Library and system folders can't be read,
so scans will undercount and report those paths as inaccessible.

To grant it:
  1. Open System Settings → Privacy & Security → Full Disk Access
       open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
  2. Turn on %s (use + to add it if it isn't listed).
  3. Quit and reopen %s, then run 'sweep doctor' again.
`, r.Terminal, r.Terminal)
	}

	fmt.Fprintf(w, "\n%s\n", report.UnitsNote)
	return nil
}
