package safety

import (
	"fmt"
	"strings"
)

// Tier is the risk classification of a finding (SPEC §6). Every finding has
// exactly one tier. Only SAFE and CAUTION can ever be deleted.
type Tier int

const (
	TierUnknown Tier = iota
	TierSafe
	TierCaution
	TierReview
	TierProtected
)

var tierNames = map[Tier]string{
	TierUnknown:   "UNKNOWN",
	TierSafe:      "SAFE",
	TierCaution:   "CAUTION",
	TierReview:    "REVIEW",
	TierProtected: "PROTECTED",
}

func (t Tier) String() string {
	if s, ok := tierNames[t]; ok {
		return s
	}
	return fmt.Sprintf("Tier(%d)", int(t))
}

// Deletable reports whether the tier may ever be part of a deletion plan.
// REVIEW, PROTECTED, and anything unrecognised are never deletable.
func (t Tier) Deletable() bool {
	return t == TierSafe || t == TierCaution
}

// ParseTier parses a tier name case-insensitively. UNKNOWN is not accepted.
func ParseTier(s string) (Tier, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	for t, name := range tierNames {
		if t != TierUnknown && name == up {
			return t, nil
		}
	}
	return TierUnknown, fmt.Errorf("unknown tier %q (want SAFE, CAUTION, REVIEW, or PROTECTED)", s)
}

func (t Tier) MarshalText() ([]byte, error) {
	if _, ok := tierNames[t]; !ok || t == TierUnknown {
		return nil, fmt.Errorf("cannot marshal tier %v", t)
	}
	return []byte(t.String()), nil
}

func (t *Tier) UnmarshalText(b []byte) error {
	v, err := ParseTier(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}
