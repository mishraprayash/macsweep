package cli

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/mishraprayash/macsweep/internal/classifier"
	"github.com/mishraprayash/macsweep/internal/report"
	"github.com/mishraprayash/macsweep/internal/rules"
	"github.com/mishraprayash/macsweep/internal/safety"
)

// engine bundles the rule set and safety guard for a home directory.
type engine struct {
	home       string
	set        *rules.Set
	guard      *safety.Guard
	configPath string
	now        func() time.Time
}

// loadEngine builds the built-in plus user rules and the safety guard.
func loadEngine(opts *globalOptions, home string) (*engine, error) {
	guard, err := safety.NewGuard(home)
	if err != nil {
		return nil, err
	}
	builtin, err := rules.Builtin()
	if err != nil {
		return nil, fmt.Errorf("built-in rules: %w", err)
	}
	cfgPath := opts.ConfigPath
	required := cfgPath != ""
	if cfgPath == "" {
		cfgPath = rules.DefaultUserConfigPath(home)
	} else {
		cfgPath = expandHome(cfgPath, home)
	}
	cfg, err := rules.LoadUserConfig(cfgPath, required)
	if err != nil {
		return nil, err
	}
	set, err := rules.NewSet(rules.Options{
		Home:     home,
		Rules:    append(builtin, cfg.Rules...),
		Excludes: cfg.Exclude,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid rules:\n%w", err)
	}
	if err := checkUserRulePaths(set, guard); err != nil {
		return nil, err
	}
	return &engine{home: home, set: set, guard: guard, configPath: cfgPath, now: time.Now}, nil
}

// checkUserRulePaths rejects user rules aimed at protected paths with a clear
// message. The safety layer would block them anyway; this just says so up
// front instead of silently overriding.
func checkUserRulePaths(set *rules.Set, guard *safety.Guard) error {
	var errs []error
	for _, r := range set.Rules() {
		if !r.User || r.Tier >= safety.TierProtected {
			continue
		}
		for _, p := range r.Match.Path {
			if reason, ok := guard.Protected(guard.Expand(p)); ok {
				errs = append(errs, fmt.Errorf("%s: rule %s: %s is protected by the safety layer (%s) and can never be cleaned", r.Source, r.ID, p, reason))
			}
		}
	}
	return errors.Join(errs...)
}

func (e *engine) classifier() *classifier.Classifier {
	return classifier.New(e.set, e.guard, e.now)
}

func renderTierTotals(w io.Writer, totals []report.TierTotal) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range totals {
		note := ""
		switch t.Tier {
		case safety.TierCaution:
			note = "  (only with --tier caution)"
		case safety.TierReview:
			note = "  (yours to review; never cleaned automatically)"
		case safety.TierProtected:
			note = "  (never deleted)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s items%s\n", report.TierLabel(t.Tier), report.Bytes(t.Size), report.Count(uint64(t.Count)), note)
	}
	return tw.Flush()
}
