package interop

import "testing"

// TestParamsArrayEnumSemantics pins CLC-v1 §6.2 (v1.1): an array grant is the set
// of allowed values, not a bound.  The harness used array-as-bound semantics
// before 2026-09-11, under which the first case below (2 against [3]) would have
// been *allowed* by recursive numeric comparison.  No other test in this
// harness distinguishes the two readings, so this file is the regression guard
// for the alignment.
func TestParamsArrayEnumSemantics(t *testing.T) {
	cases := []struct {
		name         string
		agent, grant any
		want         bool
	}{
		{"scalar-not-member", float64(2), []any{float64(3)}, false},
		{"scalar-member", float64(3), []any{float64(3)}, true},
		{"array-all-members", []any{float64(1), float64(3)}, []any{float64(1), float64(3)}, true},
		{"array-one-non-member", []any{float64(1), float64(2)}, []any{float64(1), float64(3)}, false},
		{"empty-set-denies-class", float64(1), []any{}, false},
		{"scalar-number-keeps-bound", float64(50), float64(100), true},
		{"scalar-number-exceeds-bound", float64(150), float64(100), false},
	}
	for _, c := range cases {
		if got := paramsSubset(c.agent, c.grant); got != c.want {
			t.Errorf("%s: paramsSubset(%v, %v) = %v, want %v", c.name, c.agent, c.grant, got, c.want)
		}
	}
}
