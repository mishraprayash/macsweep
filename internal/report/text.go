package report

import (
	"fmt"
	"io"
	"math"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/safety"
)

var tierColors = map[safety.Tier]*color.Color{
	safety.TierSafe:      color.New(color.FgGreen),
	safety.TierCaution:   color.New(color.FgYellow),
	safety.TierReview:    color.New(color.FgBlue),
	safety.TierProtected: color.New(color.FgRed),
}

// TierLabel is the tier name in its color: SAFE green, CAUTION yellow,
// REVIEW blue, PROTECTED red.
func TierLabel(t safety.Tier) string {
	if c, ok := tierColors[t]; ok {
		return c.Sprint(t.String())
	}
	return t.String()
}

// TextOptions controls RenderText.
type TextOptions struct {
	Home    string
	Now     time.Time
	Verbose bool
	// Width is the terminal width used for bars and wrapping (default 100).
	Width int
}

const defaultCategoryRows = 15

// RenderText writes the human-readable report.
func RenderText(w io.Writer, r *Report, o TextOptions) error {
	if o.Width < 60 {
		o.Width = 100
	}
	p := &printer{w: w, o: o, bold: color.New(color.Bold), faint: color.New(color.Faint)}

	p.linef("%s %s", p.bold.Sprint("sweep report"), p.faint.Sprintf("· scan of %s · %s (%s)",
		p.short(r.ScanRoot), Age(r.ScannedAt, o.Now), r.ScannedAt.Format("2006-01-02 15:04")))

	if r.CleanedItems > 0 {
		p.linef("%s", color.New(color.FgYellow).Sprintf("%d items (%s) were cleaned since this scan; totals below predate that. Run 'sweep scan' to refresh.",
			r.CleanedItems, Bytes(r.CleanedBytes)))
	}
	p.section(1, "Disk overview")
	p.disk(r)
	p.section(2, "Where your space is going")
	p.categories(r)
	p.section(3, `"System Data" decoded`)
	p.systemData(r)
	p.section(4, "Reclaimable space")
	p.tiers(r)
	p.section(5, fmt.Sprintf("Top %d cleanup candidates", len(r.Candidates)))
	p.candidates(r)
	p.section(6, "Stale projects")
	p.stale(r)
	p.section(7, "Largest items needing your judgment")
	p.items(r.Review, "Nothing large needs review.")
	p.section(8, "Protected (for your information)")
	p.items(r.Protected, "No large protected items.")
	p.section(9, "Next steps")
	p.next(r)

	p.linef("")
	for _, note := range []string{r.UnitsNote, r.ClonesNote} {
		for _, l := range wrapWords(note, p.o.Width) {
			p.linef("%s", p.faint.Sprint(l))
		}
	}
	return p.err
}

type printer struct {
	w           io.Writer
	o           TextOptions
	bold, faint *color.Color
	err         error
}

func (p *printer) linef(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

func (p *printer) section(n int, title string) {
	p.linef("")
	p.linef("%s", p.bold.Sprintf("%d. %s", n, title))
}

func (p *printer) short(path string) string { return tilde(path, p.o.Home) }

func (p *printer) table(rows func(tw *tabwriter.Writer), flags uint) {
	if p.err != nil {
		return
	}
	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', flags)
	rows(tw)
	p.err = tw.Flush()
}

// wrap prints text indented, wrapped to the terminal width.
func (p *printer) wrap(indent, text string) {
	for _, l := range wrapWords(text, p.o.Width-len(indent)) {
		if l != "" {
			p.linef("%s%s", indent, l)
		}
	}
}

func (p *printer) disk(r *Report) {
	d := r.Disk
	if d == nil {
		p.linef("  Disk totals were not recorded with this scan; run 'sweep scan' again.")
		return
	}
	p.table(func(tw *tabwriter.Writer) {
		fmt.Fprintf(tw, "  Disk\t%s total · %s used · %s available\n", Bytes(d.Total), Bytes(d.Used), Bytes(d.Available))
		fmt.Fprintf(tw, "  Scanned\t%s in files and folders under %s\n", Bytes(d.Scanned), p.short(r.ScanRoot))
		if len(d.OtherVolumes) > 0 {
			var parts []string
			var sum uint64
			for _, v := range d.OtherVolumes {
				sum += v.Used
				parts = append(parts, fmt.Sprintf("%s %s", v.Name, Bytes(v.Used)))
			}
			fmt.Fprintf(tw, "  Other volumes\t%s (%s)\n", Bytes(sum), strings.Join(parts, ", "))
		}
		if r.WholeDisk {
			if d.Overcounted > 0 {
				fmt.Fprintf(tw, "  Overcounted\t%s more than the disk reports as used\n", Bytes(d.Overcounted))
			} else {
				fmt.Fprintf(tw, "  Unaccounted\t%s (%.0f%% of used)\n", Bytes(d.Unaccounted), 100*share(d.Unaccounted, d.Used))
			}
		}
	}, 0)
	for _, e := range d.Explanation {
		p.wrap("  ", "→ "+e)
	}
}

func (p *printer) categories(r *Report) {
	cats := r.Categories
	hidden := 0
	if !p.o.Verbose && len(cats) > defaultCategoryRows {
		hidden = len(cats) - defaultCategoryRows
		cats = cats[:defaultCategoryRows]
	}
	if len(cats) == 0 {
		p.linef("  Nothing was scanned.")
		return
	}
	nameW := 0
	for _, c := range cats {
		nameW = max(nameW, len([]rune(c.Name)))
	}
	barW := max(10, min(30, p.o.Width-nameW-24))
	top := cats[0].Size
	for _, c := range cats {
		p.linef("  %-*s  %-*s  %9s  %3.0f%%", nameW, c.Name, barW, bar(share(c.Size, top), barW), Bytes(c.Size), c.Share*100)
	}
	if hidden > 0 {
		p.linef("  %s", p.faint.Sprintf("… %d smaller categories (--verbose shows all)", hidden))
	}
}

var eighths = []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}

// bar draws frac (0–1) of width cells with eighth-block precision.
func bar(frac float64, width int) string {
	if frac <= 0 {
		return ""
	}
	cells := frac * float64(width)
	full := int(math.Floor(cells))
	rem := int(math.Round((cells - float64(full)) * 8))
	if rem == 8 {
		full, rem = full+1, 0
	}
	s := strings.Repeat("█", full) + eighths[rem]
	if s == "" {
		s = "▏" // anything non-zero is visible
	}
	return s
}

func (p *printer) systemData(r *Report) {
	if len(r.SystemData) == 0 {
		p.linef("  Nothing to show.")
		return
	}
	nameW := 0
	for _, it := range r.SystemData {
		nameW = max(nameW, len([]rune(it.Name)))
	}
	// "  name  size  explanation", with the explanation wrapped under itself.
	indent := strings.Repeat(" ", 2+nameW+2+9+2)
	for _, it := range r.SystemData {
		size := Bytes(it.Size)
		if !it.Measured {
			size = "n/a"
		}
		lines := wrapWords(it.Explanation, max(20, p.o.Width-len(indent)))
		p.linef("  %-*s  %9s  %s", nameW, it.Name, size, p.faint.Sprint(lines[0]))
		for _, l := range lines[1:] {
			p.linef("%s%s", indent, p.faint.Sprint(l))
		}
	}
}

// wrapWords splits text into lines of at most width runes (longer words
// stay whole). It always returns at least one line.
func wrapWords(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len([]rune(line))+1+len([]rune(word)) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return append(lines, line)
}

func (p *printer) tiers(r *Report) {
	p.table(func(tw *tabwriter.Writer) {
		for _, t := range r.Tiers {
			note := ""
			switch t.Tier {
			case safety.TierSafe:
				note = "cleaned by 'sweep clean'"
			case safety.TierCaution:
				note = "only with --tier caution"
			case safety.TierReview:
				note = "yours to review; never cleaned automatically"
			case safety.TierProtected:
				note = "not deletable"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s items\t%s\n", TierLabel(t.Tier), Bytes(t.Size), Count(uint64(t.Count)), note)
		}
	}, 0)
}

func (p *printer) candidates(r *Report) {
	if len(r.Candidates) == 0 {
		p.linef("  No SAFE or CAUTION findings.")
		return
	}
	for i, it := range r.Candidates {
		mod := ""
		if !it.Modified.IsZero() {
			mod = "modified " + it.Modified.Format("2006-01-02")
		}
		pad := strings.Repeat(" ", max(0, len("PROTECTED")-len(it.Tier.String())))
		p.linef("  %2d. %9s  %s%s  %s  %s", i+1, Bytes(it.Size), TierLabel(it.Tier), pad, it.Category, p.faint.Sprint(mod))
		path := p.short(it.Path)
		if it.Stale {
			path += "  " + color.New(color.FgYellow).Sprintf("(stale: no activity since %s)", it.LastActivity.Format("2006-01-02"))
		}
		p.linef("      %s", path)
		why := it.Why
		switch {
		case it.NativeOnly:
			why += " Reclaim with: " + strings.Join(it.NativeClean, " ")
		case it.Regenerate != "":
			why += " Regenerate: " + it.Regenerate
		}
		p.wrap("      ", p.faint.Sprint(why))
	}
}

const staleRows = 15

func (p *printer) stale(r *Report) {
	if len(r.StaleProjects) == 0 {
		if r.SmallStaleProjects > 0 {
			p.linef("  %d stale projects, each with under 1 MB to reclaim.", r.SmallStaleProjects)
		} else {
			p.linef("  No stale projects with cleanable artifacts.")
		}
		return
	}
	rows := r.StaleProjects
	if !p.o.Verbose && len(rows) > staleRows {
		rows = rows[:staleRows]
	}
	p.table(func(tw *tabwriter.Writer) {
		fmt.Fprintln(tw, "  RECLAIMABLE\tIDLE SINCE\tARTIFACTS\tPROJECT")
		for _, pr := range rows {
			fmt.Fprintf(tw, "  %s\t%s (%s)\t%s\t%s\n", Bytes(pr.Reclaimable), pr.LastActivity.Format("2006-01-02"),
				Age(pr.LastActivity, p.o.Now), strings.Join(pr.Artifacts, ", "), p.short(pr.Root))
		}
	}, 0)
	if more := len(r.StaleProjects) - len(rows) + r.SmallStaleProjects; more > 0 {
		p.linef("  %s", p.faint.Sprintf("… %d more stale projects (smaller ones, or --verbose to list)", more))
	}
}

func (p *printer) items(items []Item, empty string) {
	if len(items) == 0 {
		p.linef("  %s", empty)
		return
	}
	p.table(func(tw *tabwriter.Writer) {
		for _, it := range items {
			name := p.short(it.Path)
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", Bytes(it.Size), it.Category, name)
		}
	}, 0)
	if p.o.Verbose {
		for _, it := range items {
			p.wrap("    ", p.faint.Sprintf("%s: %s", p.short(it.Path), it.Why))
		}
	} else {
		p.linef("  %s", p.faint.Sprint("--verbose explains each item; 'sweep explain <path>' explains one."))
	}
}

func (p *printer) next(r *Report) {
	for _, s := range r.NextSteps {
		p.linef("  %s", s.Command)
		for _, l := range wrapWords(s.Why, p.o.Width-6) {
			p.linef("      %s", p.faint.Sprint(l))
		}
	}
}
