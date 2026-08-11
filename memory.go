package cerberus

// The REFERENCE implementation of the scan grammar.
//
// 🔑 IT DEFINES THE SEMANTICS. An adapter — a SQL one, a columnar one, anything — is correct
// exactly insofar as it agrees with this on the conformance vectors in ./conformance. That is the
// only way "our adapter is equivalent" becomes a claim somebody can check rather than a hope.

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// MemoryScanner is the REFERENCE implementation of the grammar.
//
// It defines the semantics. A SQL adapter is correct exactly insofar as it agrees with this on the
// conformance vectors — which is the only way "an adapter is equivalent" can be a claim rather
// than a hope. Today nothing could be checked that way.
type MemoryScanner struct {
	Observations []Observation
	// Now anchors the trailing window. Injected rather than read from the clock so a vector is
	// reproducible.
	Now time.Time
}

// NewMemoryScanner builds the reference adapter.
func NewMemoryScanner(obs []Observation, now time.Time) *MemoryScanner {
	return &MemoryScanner{Observations: obs, Now: now}
}

// Capabilities: the reference serves the whole grammar, by construction.
func (m *MemoryScanner) Capabilities() Capabilities {
	return Capabilities{
		Sources:    []Source{SourceArrivalStream, SourceAcceptedOnly},
		Units:      []Unit{UnitEvent, UnitSession, UnitSessionFirstEvent},
		Groups:     []GroupKey{GroupDeviceCohort, GroupFingerprint, GroupSite, GroupOwner, GroupCountry, GroupTimezone, GroupReferrer},
		Aggregates: []Aggregate{AggRayleigh, AggHHI, AggDistinctCount, AggModalShare, AggChain},
		Fields: []Field{FieldTimestamp, FieldTimezoneResolvable, FieldCountry, FieldCity,
			FieldDuration, FieldScrollDepth, FieldReferrer, FieldASNClass, FieldUAClass},
	}
}

// tzAliases maps zones Postgres does not know onto ones it does. Legacy names matter: one of them
// covered 133 production sessions and was invisible to every timezone rule because only the modern
// spelling was listed.
var tzAliases = map[string]string{
	"Asia/Calcutta":        "Asia/Kolkata",
	"Asia/Katmandu":        "Asia/Kathmandu",
	"Europe/Kiev":          "Europe/Kyiv",
	"Asia/Saigon":          "Asia/Ho_Chi_Minh",
	"America/Buenos_Aires": "America/Argentina/Buenos_Aires",
	"America/Indianapolis": "America/Indiana/Indianapolis",
}

// resolveTZ resolves a browser-supplied zone, FAIL-CLOSED.
//
// 🔑 This is a published conformance requirement, not an implementation detail. In Postgres,
// `AT TIME ZONE` on a zone the server does not know ABORTS THE QUERY — it does not skip the row —
// so an adapter that renders it naively turns one unknown zone into zero results for the whole
// scan. Dropping the row is the only behaviour that degrades safely, and an adapter that aborts
// instead is not equivalent however similar its numbers look on clean data.
// ResolveTZ is resolveTZ, exported so a rule can use the SAME resolution the reference scanner
// defines. Two implementations of "which zones resolve" is two answers to a question that has to
// have one, and the fail-closed behaviour is a published conformance requirement rather than an
// implementation detail.
func ResolveTZ(name string) (*time.Location, bool) { return resolveTZ(name) }

func resolveTZ(name string) (*time.Location, bool) {
	if name == "" {
		return nil, false
	}
	if alias, ok := tzAliases[name]; ok {
		name = alias
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, false
	}
	return loc, true
}

// Scan runs the spec against the in-memory observations.
func (m *MemoryScanner) Scan(s Spec) (Result, error) {
	if err := s.Validate(); err != nil {
		return Result{}, err
	}
	if err := m.Capabilities().Supports(s); err != nil {
		return Result{}, err
	}

	from := m.Now.AddDate(0, 0, -s.Window.Days)
	rows := m.selectRows(s, from)
	rows = m.reduceToUnit(rows, s.Unit)

	buckets := map[string][]Observation{}
	for _, o := range rows {
		buckets[groupKeyOf(o, s.GroupBy)] = append(buckets[groupKeyOf(o, s.GroupBy)], o)
	}

	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := Result{Spec: s}
	for _, k := range keys {
		bucket := buckets[k]
		if len(bucket) < s.MinUnits {
			continue
		}
		value, err := aggregate(s, bucket)
		if err != nil {
			return Result{}, err
		}
		out.Groups = append(out.Groups, Group{
			Key:      k,
			Units:    len(bucket),
			Value:    value,
			Sessions: sessionsOf(bucket),
		})
	}

	// * Unreachable: no bucket in the whole substrate could reach the floor, so the rule cannot
	// * fire under this data whatever its threshold. Saying so is what stops a structurally blind
	// * rule reporting "no finding" and reading as if it worked.
	if len(out.Groups) == 0 {
		biggest := 0
		for _, b := range buckets {
			if len(b) > biggest {
				biggest = len(b)
			}
		}
		out.Unreachable = biggest < s.MinUnits
	}
	return out, nil
}

func (m *MemoryScanner) selectRows(s Spec, from time.Time) []Observation {
	needTZ := false
	for _, f := range s.RequireFields {
		if f == FieldTimezoneResolvable {
			needTZ = true
		}
	}

	var out []Observation
	for i := range m.Observations {
		o := m.Observations[i]

		if s.Source == SourceAcceptedOnly && o.Arrival != ArrivalAccepted {
			continue
		}
		// * VerdictNone deliberately keeps convicted rows: a re-derivation that cannot see what it
		// * convicted revokes its own verdict the moment it runs.
		if s.VerdictFilter == VerdictExclude && o.Arrival == ArrivalQuarantined {
			continue
		}

		switch s.Window.Boundary {
		case BoundaryInclusiveExclusive:
			if o.Timestamp.Before(from) || !o.Timestamp.Before(m.Now) {
				continue
			}
		case BoundaryExclusiveInclusive:
			if !o.Timestamp.After(from) || o.Timestamp.After(m.Now) {
				continue
			}
		}

		if needTZ {
			if o.Timezone == nil {
				continue
			}
			if _, ok := resolveTZ(*o.Timezone); !ok {
				continue
			}
		}
		out = append(out, o)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

func (m *MemoryScanner) reduceToUnit(obs []Observation, u Unit) []Observation {
	if u == UnitEvent {
		return obs
	}
	first := map[string]int{}
	var order []string
	for i := range obs {
		k := obs[i].SiteID + "|" + obs[i].SessionID
		prev, seen := first[k]
		if !seen {
			first[k] = i
			order = append(order, k)
			continue
		}
		if obs[i].Timestamp.Before(obs[prev].Timestamp) {
			first[k] = i
		}
	}
	out := make([]Observation, 0, len(order))
	for _, k := range order {
		out = append(out, obs[first[k]])
	}
	return out
}

func groupKeyOf(o Observation, keys []GroupKey) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		switch k {
		case GroupDeviceCohort:
			parts = append(parts, o.DeviceCohort())
		case GroupFingerprint:
			parts = append(parts, o.Fingerprint())
		case GroupSite:
			parts = append(parts, o.SiteID)
		case GroupOwner:
			parts = append(parts, o.OwnerID)
		case GroupCountry:
			parts = append(parts, deref(o.Country))
		case GroupTimezone:
			parts = append(parts, deref(o.Timezone))
		case GroupReferrer:
			parts = append(parts, deref(o.Referrer))
		}
	}
	return joinKeys(parts)
}

func aggregate(s Spec, bucket []Observation) (float64, error) {
	switch s.Aggregate {
	case AggDistinctCount:
		seen := map[string]bool{}
		for _, o := range bucket {
			seen[deref(o.Timezone)] = true
		}
		return float64(len(seen)), nil

	case AggModalShare:
		counts := map[string]int{}
		for _, o := range bucket {
			counts[deref(o.City)]++
		}
		best := 0
		for _, n := range counts {
			if n > best {
				best = n
			}
		}
		return float64(best) / float64(len(bucket)), nil

	case AggHHI:
		counts := map[string]int{}
		for _, o := range bucket {
			counts[deref(o.Country)]++
		}
		var h float64
		for _, n := range counts {
			share := float64(n) / float64(len(bucket))
			h += share * share
		}
		return h, nil

	case AggRayleigh:
		// * Z = n·R² over local hour. Phase-invariant on purpose: a χ² against the site's hourly
		// * profile is more powerful but PHASE-SENSITIVE, so it convicts populations whose declared
		// * clock is displaced from their real one — the diaspora, which is the single population
		// * every realised false positive has come from.
		var sumCos, sumSin float64
		var n int
		for _, o := range bucket {
			if o.Timezone == nil {
				continue
			}
			loc, ok := resolveTZ(*o.Timezone)
			if !ok {
				continue
			}
			local := o.Timestamp.In(loc)
			theta := 2 * math.Pi * float64(local.Hour()*3600+local.Minute()*60+local.Second()) / 86400
			sumCos += math.Cos(theta)
			sumSin += math.Sin(theta)
			n++
		}
		if n == 0 {
			return 0, nil
		}
		r := math.Hypot(sumCos/float64(n), sumSin/float64(n))
		return float64(n) * r * r, nil

	case AggChain:
		// * Longest run of observations whose consecutive gaps stay inside the gap.
		gap := time.Duration(s.ChainGapSeconds * float64(time.Second))
		best, run := 1, 1
		for i := 1; i < len(bucket); i++ {
			if bucket[i].Timestamp.Sub(bucket[i-1].Timestamp) <= gap {
				run++
			} else {
				run = 1
			}
			if run > best {
				best = run
			}
		}
		return float64(best), nil

	default:
		return 0, fmt.Errorf("cerberus: unimplemented aggregate %q", s.Aggregate)
	}
}

func sessionsOf(bucket []Observation) []SessionRef {
	seen := map[SessionRef]bool{}
	var out []SessionRef
	for _, o := range bucket {
		ref := SessionRef{SiteID: o.SiteID, SessionID: o.SessionID}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SiteID != out[j].SiteID {
			return out[i].SiteID < out[j].SiteID
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out
}

func joinKeys(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "|"
		}
		out += p
	}
	return out
}
