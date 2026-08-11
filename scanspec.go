package cerberus

// The closed, declarative grammar a detector uses to ask for evidence.
//
// 🔑 WHY A GRAMMAR AND NOT A QUERY. A rule that writes its own SQL puts the parts of itself that
// carry its meaning on the private side of any boundary, where no conformance test can reach them.
// FIVE such parts turned out to be load-bearing rather than incidental:
//
//  1. the window boundary convention — which end is inclusive;
//  2. the DEDUP UNIT. Counting events where the rule means SESSIONS pseudo-replicates a real
//     cohort's engagement across many rows and drives a concentration statistic toward a
//     conviction. That is not a detail; it is the difference between two different rules, and it
//     SHIPPED AS A BUG. It is the single most important thing in this file;
//  3. fail-closed timezone resolution — in PostgreSQL 16, `AT TIME ZONE` on a browser-supplied zone
//     the server does not know ABORTS THE QUERY rather than skipping the row, so a naive adapter
//     turns one unknown zone into zero results for the whole scan;
//  4. the arrival-stream union — measuring on accepted traffic alone reports no false positives
//     because it convicts nothing;
//  5. whether the scan filters on verdict state. An adapter whose scan excludes convicted rows has
//     a re-derivation that revokes on absence, and its numbers diverge silently.
//
// 🔴 WHY NOT A DSL. A general expression language over event fields would make writing another
// "this key did N of X in window W" counter the easiest thing in the system — the exact shape this
// design exists to remove — and it would make every rule individually unanalysable. This is a
// parameterisation of a CLOSED REGISTRY of named aggregates. Suricata/Sigma shape, not eBPF shape.
//
// The port collapses to one method, Scan(Spec), so adding a rule adds an enum VALUE rather than a
// method. That is what makes the additive-only promise in this module's doc.go true rather than
// aspirational.

import (
	"fmt"
	"sort"
	"strings"
)

// Source selects the substrate.
type Source string

const (
	// SourceArrivalStream is accepted ∪ quarantined: traffic as it ARRIVED.
	SourceArrivalStream Source = "arrival_stream"
	// SourceAcceptedOnly measures the residue after the incumbent swept. Valid only for
	// deliberately reproducing a historical mismeasurement.
	SourceAcceptedOnly Source = "accepted_only"
)

// VerdictFilter decides whether already-convicted rows are visible to the scan.
type VerdictFilter string

const (
	// VerdictNone shows convicted rows. Every shipped rule uses this: a re-derivation that cannot
	// see the rows it convicted would revoke its own verdict the moment it ran.
	VerdictNone VerdictFilter = "none"
	// VerdictExclude hides them.
	VerdictExclude VerdictFilter = "exclude_verdict"
)

// Unit is the unit of observation.
type Unit string

const (
	UnitEvent             Unit = "event"
	UnitSession           Unit = "session"
	UnitSessionFirstEvent Unit = "session_first_event"
)

// GroupKey is the CLOSED vocabulary of grouping keys.
//
// 🔑 There is deliberately no key that produces a (fingerprint, site) tuple. A grouping that
// enumerates which sites a device configuration appeared on is a cross-site visitor record, which
// is the one thing the product promises not to build. Cross-tenant reasoning may produce a COUNT;
// it must never produce a membership list. Enforced by TestSpecCannotExpressCrossTenantMembership.
type GroupKey string

const (
	// GroupDeviceCohort is browser|os|device_type|language|screen_resolution — timezone excluded,
	// because collapsing timezone is what makes a rotation visible.
	GroupDeviceCohort GroupKey = "device_cohort"
	// GroupFingerprint is the device cohort plus the declared timezone.
	GroupFingerprint GroupKey = "fingerprint"
	GroupSite        GroupKey = "site"
	GroupOwner       GroupKey = "owner"
	GroupCountry     GroupKey = "country"
	GroupTimezone    GroupKey = "timezone"
	GroupReferrer    GroupKey = "referrer_label"
)

// Aggregate is the CLOSED registry of statistics a scan may compute.
type Aggregate string

const (
	// AggRayleigh is circular concentration over local hour: does this population sleep?
	AggRayleigh Aggregate = "rayleigh"
	// AggHHI is concentration over a categorical distribution.
	AggHHI Aggregate = "hhi"
	// AggDistinctCount counts distinct values of the grouped field.
	AggDistinctCount Aggregate = "distinct_count"
	// AggModalShare is the share held by the single most common value.
	AggModalShare Aggregate = "modal_share"
	// AggChain links observations whose timestamps fall within a gap.
	AggChain Aggregate = "chain"
)

// Field is a required input a scan declares. Declaring it lets the harness refuse to run outside
// the window in which that field is trustworthy, rather than returning a confident zero.
type Field string

const (
	FieldTimestamp          Field = "timestamp"
	FieldTimezoneResolvable Field = "timezone_resolvable"
	FieldCountry            Field = "country"
	FieldCity               Field = "city"
	FieldDuration           Field = "duration"
	FieldScrollDepth        Field = "scroll_depth"
	FieldReferrer           Field = "referrer"
	FieldASNClass           Field = "asn_class"
	FieldUAClass            Field = "ua_class"
)

// Boundary names which end of a window is inclusive.
type Boundary string

const (
	BoundaryInclusiveExclusive Boundary = "inclusive_exclusive"
	BoundaryExclusiveInclusive Boundary = "exclusive_inclusive"
)

// Window is a trailing time window.
type Window struct {
	Days     int      `json:"days" yaml:"days"`
	Boundary Boundary `json:"boundary" yaml:"boundary"`
	// Clock is always UTC. The field exists so the convention is stated in the artefact rather
	// than assumed, because a per-site clock is exactly the kind of thing someone adds later.
	Clock string `json:"clock" yaml:"clock"`
}

// Spec is a complete, declarative request for evidence.
type Spec struct {
	Source        Source        `json:"source" yaml:"source"`
	VerdictFilter VerdictFilter `json:"verdict_filter" yaml:"verdict_filter"`
	Unit          Unit          `json:"unit" yaml:"unit"`
	GroupBy       []GroupKey    `json:"group_by" yaml:"group_by"`
	Window        Window        `json:"window" yaml:"window"`
	RequireFields []Field       `json:"require_fields" yaml:"require_fields"`
	Aggregate     Aggregate     `json:"aggregate" yaml:"aggregate"`
	MinUnits      int           `json:"min_units" yaml:"min_units"`
	// ChainGapSeconds applies to AggChain only.
	ChainGapSeconds float64 `json:"chain_gap_seconds,omitempty" yaml:"chain_gap_seconds,omitempty"`
}

// Validation errors, each naming the mistake.
var (
	ErrSourceInvalid    = fmt.Errorf("cerberus: source must be arrival_stream or accepted_only")
	ErrVerdictInvalid   = fmt.Errorf("cerberus: verdict_filter must be none or exclude_verdict")
	ErrUnitInvalid      = fmt.Errorf("cerberus: unit must be event, session or session_first_event")
	ErrGroupInvalid     = fmt.Errorf("cerberus: group_by contains a key outside the closed vocabulary")
	ErrGroupEmpty       = fmt.Errorf("cerberus: group_by must name at least one key")
	ErrAggregateInvalid = fmt.Errorf("cerberus: aggregate is not in the closed registry")
	ErrWindowInvalid    = fmt.Errorf("cerberus: window days must be positive and boundary must be stated")
	ErrFieldInvalid     = fmt.Errorf("cerberus: require_fields contains an unknown field")
	ErrMinUnitsInvalid  = fmt.Errorf("cerberus: min_units must be positive")
	ErrChainGapMissing  = fmt.Errorf("cerberus: aggregate chain requires a positive chain_gap_seconds")
)

var (
	validGroups = map[GroupKey]bool{
		GroupDeviceCohort: true, GroupFingerprint: true, GroupSite: true,
		GroupOwner: true, GroupCountry: true, GroupTimezone: true, GroupReferrer: true,
	}
	validAggregates = map[Aggregate]bool{
		AggRayleigh: true, AggHHI: true, AggDistinctCount: true,
		AggModalShare: true, AggChain: true,
	}
	validFields = map[Field]bool{
		FieldTimestamp: true, FieldTimezoneResolvable: true, FieldCountry: true,
		FieldCity: true, FieldDuration: true, FieldScrollDepth: true,
		FieldReferrer: true, FieldASNClass: true, FieldUAClass: true,
	}
)

// Validate rejects a spec the grammar does not admit. Every enum is closed, so a typo is an error
// rather than a silently-empty scan.
func (s Spec) Validate() error {
	switch s.Source {
	case SourceArrivalStream, SourceAcceptedOnly:
	default:
		return ErrSourceInvalid
	}
	switch s.VerdictFilter {
	case VerdictNone, VerdictExclude:
	default:
		return ErrVerdictInvalid
	}
	switch s.Unit {
	case UnitEvent, UnitSession, UnitSessionFirstEvent:
	default:
		return ErrUnitInvalid
	}
	if len(s.GroupBy) == 0 {
		return ErrGroupEmpty
	}
	for _, g := range s.GroupBy {
		if !validGroups[g] {
			return fmt.Errorf("%w: %q", ErrGroupInvalid, g)
		}
	}
	if !validAggregates[s.Aggregate] {
		return fmt.Errorf("%w: %q", ErrAggregateInvalid, s.Aggregate)
	}
	for _, f := range s.RequireFields {
		if !validFields[f] {
			return fmt.Errorf("%w: %q", ErrFieldInvalid, f)
		}
	}
	if s.Window.Days <= 0 || (s.Window.Boundary != BoundaryInclusiveExclusive && s.Window.Boundary != BoundaryExclusiveInclusive) {
		return ErrWindowInvalid
	}
	if s.MinUnits <= 0 {
		return ErrMinUnitsInvalid
	}
	if s.Aggregate == AggChain && s.ChainGapSeconds <= 0 {
		return ErrChainGapMissing
	}
	return nil
}

// Key is the canonical string form of a spec, used to compare two adapters' understanding of the
// same request and to stamp a report.
func (s Spec) Key() string {
	groups := make([]string, len(s.GroupBy))
	for i, g := range s.GroupBy {
		groups[i] = string(g)
	}
	fields := make([]string, len(s.RequireFields))
	for i, f := range s.RequireFields {
		fields[i] = string(f)
	}
	sort.Strings(fields)
	return fmt.Sprintf("source=%s verdict=%s unit=%s group=[%s] window=%dd/%s/%s fields=[%s] agg=%s min=%d gap=%g",
		s.Source, s.VerdictFilter, s.Unit, strings.Join(groups, "+"),
		s.Window.Days, s.Window.Boundary, s.Window.Clock,
		strings.Join(fields, ","), s.Aggregate, s.MinUnits, s.ChainGapSeconds)
}

// Group is one grouped bucket of a scan.
//
// 🔑 It carries COUNTS and the group key, never a list of the members. An adopter cannot use this
// result to learn which sites a device configuration visited, because the shape does not admit it.
type Group struct {
	Key   string  `json:"key"`
	Units int     `json:"units"`
	Value float64 `json:"value"`
	// Sessions are the sessions in this group, present ONLY so a verdict can enumerate what it
	// convicts — a hash is a population, not a device, and a verdict must name its members rather
	// than expand to every session that ever carried the key.
	Sessions []SessionRef `json:"sessions,omitempty"`
}

// Result is what an adapter returns.
type Result struct {
	Spec   Spec    `json:"spec"`
	Groups []Group `json:"groups"`
	// Unreachable is true when the scan could not have produced a finding under any data — for
	// example a bar higher than the substrate can reach. A rule that is structurally unable to
	// fire must say so rather than report "no finding", which is indistinguishable from working.
	Unreachable bool `json:"unreachable"`
}

// Capabilities declares what an adapter can serve. A pack requiring an unavailable feature must
// fail to LOAD, loudly, naming the detector — today the equivalent failure is silent: the
// fingerprint silence path needs a column present on 2.8% of events and has fired zero times ever,
// with nothing anywhere saying so.
type Capabilities struct {
	Sources    []Source
	Units      []Unit
	Groups     []GroupKey
	Aggregates []Aggregate
	Fields     []Field
}

// Supports reports whether the adapter can serve the spec, naming the first thing it cannot.
func (c Capabilities) Supports(s Spec) error {
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}
	var sources, units, groups, aggs, fields []string
	for _, x := range c.Sources {
		sources = append(sources, string(x))
	}
	for _, x := range c.Units {
		units = append(units, string(x))
	}
	for _, x := range c.Groups {
		groups = append(groups, string(x))
	}
	for _, x := range c.Aggregates {
		aggs = append(aggs, string(x))
	}
	for _, x := range c.Fields {
		fields = append(fields, string(x))
	}

	if !has(sources, string(s.Source)) {
		return fmt.Errorf("adapter cannot serve source %q", s.Source)
	}
	if !has(units, string(s.Unit)) {
		return fmt.Errorf("adapter cannot serve unit %q", s.Unit)
	}
	for _, g := range s.GroupBy {
		if !has(groups, string(g)) {
			return fmt.Errorf("adapter cannot group by %q", g)
		}
	}
	if !has(aggs, string(s.Aggregate)) {
		return fmt.Errorf("adapter cannot compute %q", s.Aggregate)
	}
	for _, f := range s.RequireFields {
		if !has(fields, string(f)) {
			return fmt.Errorf("adapter cannot supply field %q", f)
		}
	}
	return nil
}

// Scanner is the whole port. One method, plus what it can do.
//
// Adding a rule adds an enum value, not a method — which is what makes the schema module's
// additive-only promise true rather than aspirational.
type Scanner interface {
	Scan(Spec) (Result, error)
	Capabilities() Capabilities
}
