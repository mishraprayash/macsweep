package rules

// Detector describes the built-in code behind a synthetic rule. Every
// synthetic built-in rule must have one (TestSyntheticRulesHaveDetectors).
type Detector struct {
	// Summary says how the detector decides, for 'sweep rules show'.
	Summary string
	// ToolManaged means what it finds is owned by a tool (old versions in a
	// version store), so the cleaner skips its .git/.env content check.
	// Anything else, such as an uninstalled app's data, is checked.
	ToolManaged bool
}

// HomebrewRuleID is the synthetic rule for old Homebrew formula versions,
// found by the classifier's Homebrew detector.
const HomebrewRuleID = "homebrew-old-versions"

// detectors lists the detectors that are not version stores (those are
// listed in versionStores).
var detectors = map[string]Detector{
	HomebrewRuleID: {Summary: "decided by sweep's Homebrew detector, which keeps the linked version", ToolManaged: true},
	LeftoverRuleID: {Summary: "decided by sweep's leftover detector, which checks the apps installed right now"},
}

var versionStoreDetector = Detector{Summary: "decided by sweep's version detector, which keeps the version in use", ToolManaged: true}

// DetectorFor returns the detector behind a synthetic rule.
func DetectorFor(ruleID string) (Detector, bool) {
	if d, ok := detectors[ruleID]; ok {
		return d, true
	}
	for _, vs := range versionStores {
		if vs.ruleID == ruleID {
			return versionStoreDetector, true
		}
	}
	return Detector{}, false
}
