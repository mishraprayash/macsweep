package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/safety"
)

type explainOutput struct {
	classifier.Explanation
	Clean string `json:"clean"`
}

// cleanVerdict says, in one sentence, what 'sweep clean' would do with it.
func cleanVerdict(e classifier.Explanation) string {
	inside := ""
	if e.MatchedPath != "" && e.MatchedPath != e.Path {
		inside = " (as part of the enclosing match)"
	}
	switch e.Tier {
	case safety.TierSafe, safety.TierCaution:
		how := "moved to the Trash"
		switch {
		case e.NativeOnly:
			how = "reclaimed only by running `" + strings.Join(e.NativeClean, " ") + "`; the files are never deleted directly"
		case len(e.NativeClean) > 0:
			how = "cleaned by running `" + strings.Join(e.NativeClean, " ") + "`"
		case e.CleanContents:
			how = "emptied (its contents removed)"
		}
		flag := "included in 'sweep clean' by default"
		if e.Tier == safety.TierCaution {
			flag = "included only with 'sweep clean --tier caution'"
		}
		return fmt.Sprintf("%s%s; %s.", capitalize(flag), inside, how)
	case safety.TierReview:
		return "Never cleaned automatically. sweep lists it so you can decide."
	default:
		return "Never deleted by sweep."
	}
}

func renderExplain(w io.Writer, o explainOutput, home string) error {
	bold, faint := color.New(color.Bold), color.New(color.Faint)
	e := o.Explanation

	title := shortPath(e.Path, home)
	if !e.Exists {
		title += faint.Sprint("  (does not exist)")
	}
	fmt.Fprintln(w, bold.Sprint(title))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "  %s\t%s\n", k, v)
		}
	}
	row("Tier", report.TierLabel(e.Tier)+"  "+tierMeaning(e.Tier))
	if e.Override != "" {
		base := "the rule said " + e.RuleTier
		if e.Unclassified {
			base = "otherwise " + e.RuleTier
		}
		row("Override", fmt.Sprintf("%s (%s)", e.Override, base))
	}
	if e.Unclassified {
		if e.RuleTier == safety.TierReview.String() {
			row("Rule", "none: unclassified, likely user data")
		} else {
			row("Rule", "none: unclassified, outside your home folder")
		}
	} else {
		row("Rule", fmt.Sprintf("%s · %s  %s", e.RuleID, e.Category, faint.Sprintf("(%s)", e.RuleSource)))
		if e.MatchedPath != e.Path {
			row("Inside", shortPath(e.MatchedPath, home))
		}
		row("Why", e.Reason)
		row("What", e.Description)
		row("Regenerate", e.RegenerateHint)
		row("Pending", e.Pending)
	}
	if e.ProjectRoot != "" {
		p := shortPath(e.ProjectRoot, home)
		if !e.LastActivity.IsZero() {
			p += fmt.Sprintf(" · last activity %s (%s)", e.LastActivity.Format("2006-01-02"), report.Age(e.LastActivity, time.Now()))
			if e.Stale {
				p += " · " + color.New(color.FgYellow).Sprint("stale")
			}
		}
		row("Project", p)
	}
	switch {
	case e.SizeKnown && !e.ScannedAt.IsZero():
		row("Size", fmt.Sprintf("%s (scan from %s)", report.Bytes(e.Size), report.Age(e.ScannedAt, time.Now())))
	case e.SizeKnown:
		row("Size", report.Bytes(e.Size))
	case e.InScan && e.Exists:
		row("Size", "under 1 MB (small folders are folded into their parent in the saved scan)")
	default:
		row("Size", "unknown; run 'sweep scan' on a folder containing it")
	}
	row("Clean", o.Clean)
	return tw.Flush()
}

func tierMeaning(t safety.Tier) string {
	switch t {
	case safety.TierSafe:
		return "fully regenerable, no user state"
	case safety.TierCaution:
		return "regenerable, but costly or may hold state"
	case safety.TierReview:
		return "may be your data; review it yourself"
	default:
		return "system or critical personal data"
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
