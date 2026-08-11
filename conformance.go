package cerberus

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"time"
)

//go:embed conformance/*.json
var conformanceFS embed.FS

// Vector is one conformance case: a fixed substrate, a fixed clock, a spec, and the result any
// correct adapter must produce.
//
// 🔑 THESE ARE THE POINT OF THE MODULE. The types alone would let two implementations agree on
// every field name and disagree on every answer. A vector is executable: an adapter runs
// CheckVector against its own Scanner and either matches or does not.
//
// The clock is in the vector rather than read from the machine so a case is reproducible; a
// conformance suite that passes on Tuesdays is not a conformance suite.
type Vector struct {
	Name string `json:"name"`
	// Why states what a failure of this case would mean in production. It is not decoration: a
	// vector whose purpose nobody can state is a vector that gets deleted the first time it is
	// inconvenient.
	Why          string        `json:"why"`
	Now          time.Time     `json:"now"`
	Observations []Observation `json:"observations"`
	Spec         Spec          `json:"spec"`
	Expect       ExpectedGroup `json:"expect"`
}

// ExpectedGroup is the assertion. Groups are compared by key, unit count and value; sessions are
// compared as a set, because a verdict must be able to enumerate its members and an adapter that
// returns the right count over the wrong members is not equivalent.
type ExpectedGroup struct {
	// Unreachable asserts the "no bucket could have reached the floor" flag. A rule that is
	// structurally unable to fire must SAY SO rather than report no finding, which is
	// indistinguishable from working.
	Unreachable bool            `json:"unreachable"`
	Groups      []ExpectedEntry `json:"groups"`
}

// ExpectedEntry is one expected bucket.
type ExpectedEntry struct {
	Key      string   `json:"key"`
	Units    int      `json:"units"`
	Value    *float64 `json:"value,omitempty"`
	Sessions []string `json:"sessions,omitempty"` // "site|session", sorted
}

// Vectors returns every embedded conformance vector, ordered by file name.
func Vectors() ([]Vector, error) {
	entries, err := fs.Glob(conformanceFS, "conformance/*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	out := make([]Vector, 0, len(entries))
	for _, e := range entries {
		b, err := conformanceFS.ReadFile(e)
		if err != nil {
			return nil, err
		}
		var v Vector
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", path.Base(e), err)
		}
		if v.Name == "" {
			return nil, fmt.Errorf("%s: vector has no name", path.Base(e))
		}
		if v.Why == "" {
			return nil, fmt.Errorf("%s: vector %q does not say what its failure would mean", path.Base(e), v.Name)
		}
		out = append(out, v)
	}
	return out, nil
}

// CheckVector runs one vector against a Scanner and reports every disagreement.
//
// It returns a list rather than the first error on purpose: an adapter that is wrong about the
// dedup unit is usually wrong about several buckets at once, and seeing one of them is how a
// systematic difference gets fixed as a special case.
func CheckVector(s Scanner, v Vector) []error {
	var errs []error
	res, err := s.Scan(v.Spec)
	if err != nil {
		return []error{fmt.Errorf("%s: scan: %w", v.Name, err)}
	}

	if res.Unreachable != v.Expect.Unreachable {
		errs = append(errs, fmt.Errorf("%s: unreachable = %v, want %v — a rule that cannot fire "+
			"under any data must say so rather than report no finding", v.Name, res.Unreachable, v.Expect.Unreachable))
	}
	if len(res.Groups) != len(v.Expect.Groups) {
		errs = append(errs, fmt.Errorf("%s: %d groups, want %d", v.Name, len(res.Groups), len(v.Expect.Groups)))
	}

	got := map[string]Group{}
	for _, g := range res.Groups {
		got[g.Key] = g
	}
	for _, want := range v.Expect.Groups {
		g, ok := got[want.Key]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no group %q in the result", v.Name, want.Key))
			continue
		}
		if g.Units != want.Units {
			errs = append(errs, fmt.Errorf("%s: group %q has %d units, want %d", v.Name, want.Key, g.Units, want.Units))
		}
		if want.Value != nil && !nearly(g.Value, *want.Value) {
			errs = append(errs, fmt.Errorf("%s: group %q value = %g, want %g", v.Name, want.Key, g.Value, *want.Value))
		}
		if want.Sessions != nil {
			gotSessions := make([]string, 0, len(g.Sessions))
			for _, r := range g.Sessions {
				gotSessions = append(gotSessions, r.SiteID+"|"+r.SessionID)
			}
			sort.Strings(gotSessions)
			wantSessions := append([]string(nil), want.Sessions...)
			sort.Strings(wantSessions)
			if !equalStrings(gotSessions, wantSessions) {
				errs = append(errs, fmt.Errorf("%s: group %q members = %v, want %v — the count can "+
					"be right while the membership is wrong, and a verdict enumerates its members",
					v.Name, want.Key, gotSessions, wantSessions))
			}
		}
	}
	return errs
}

// nearly compares floats with a tolerance wide enough for a different summation order and narrow
// enough to catch a different statistic.
func nearly(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
