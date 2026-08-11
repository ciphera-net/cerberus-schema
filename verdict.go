package cerberus

// Class decides ENFORCEMENT MODE. It never decides a weight.
//
// 🔑 THE SEPARATION IS THE WHOLE IDEA. The engine this schema was extracted from previously
// conflated "how suspicious is this" with "how safe is it to act on this", scored the two together,
// and then let a single inferred signal delete an event. Class answers only the second question,
// and a numeric score answers neither.
type Class string

const (
	// ClassDeclared — the client says it is a machine.
	ClassDeclared Class = "declared"
	// ClassConstructive — true by construction rather than by correlation: a path no human is ever
	// served, requested.
	ClassConstructive Class = "constructive"
	// ClassPhysical — a physical impossibility, e.g. sessions born microseconds apart declaring
	// different clocks. One device has one clock.
	ClassPhysical Class = "physical"
	// ClassPopulation — a property of a COHORT, never of a visitor. A population verdict that
	// expands from its key to every session that ever wore that key is the shape behind every mass
	// false positive this engine has produced.
	ClassPopulation Class = "population"
	// ClassCrossTenant — a coincidence across unrelated customers.
	ClassCrossTenant Class = "cross_tenant"
	// ClassCircumstance — a real hardened or travelling human produces these. It may inform a
	// finding. It may NEVER convict, at any multiplicity: a timezone/GeoIP mismatch measured 99%
	// human on 283 production sessions.
	ClassCircumstance Class = "circumstance"
)

// Provenance records where a fact came from.
//
// 🔴 A CLIENT-ASSERTED FACT MAY INFORM A FINDING AND MUST NEVER REVOKE A VERDICT. The engagement
// fields on Observation arrive over an endpoint that accepts any event id, so a rebuttal built from
// them is an attacker-supplied acquittal. Provenance exists so that rule is checkable rather than
// remembered.
type Provenance string

const (
	ProvenanceObserved       Provenance = "observed"        // measured server-side
	ProvenanceDerived        Provenance = "derived"         // computed from observed facts
	ProvenanceClientAsserted Provenance = "client_asserted" // the page said so
)

// Strength is how firmly a verdict is held. It drives TTL, not enforcement.
type Strength string

const (
	StrengthConclusive Strength = "conclusive"
	StrengthStrong     Strength = "strong"
	StrengthFinding    Strength = "finding"
)

// Action is what a verdict authorises.
type Action string

const (
	// ActionConvict — enforceable.
	ActionConvict Action = "convict"
	// ActionFinding — recorded and surfaced, NEVER enforced. This is how the system says "we saw
	// something" without acting on it, and it is the state most evidence should reach.
	ActionFinding Action = "finding"
)

// Evidence is one item supporting a verdict.
type Evidence struct {
	// RuleID is the detector that produced it.
	RuleID string `json:"rule_id"`

	// Family is the INDEPENDENCE KEY, and it is the field most likely to be got wrong by an
	// adopter. Two items sharing a family are ONE item. Without it, three restatements of a single
	// observation look exactly like three corroborating detectors — which is how a quorum gets
	// bought for free.
	Family string `json:"family"`

	// IndependenceGroup collapses families that are not actually independent OF EACH OTHER. Empty
	// means the family is its own group. Two rules reading the same underlying distribution — say
	// a country concentration and a single-egress test, both readings of one GeoIP answer — share
	// a group even though they have different names, and a quorum must count them once.
	IndependenceGroup string `json:"independence_group,omitempty"`

	Class      Class      `json:"class"`
	Provenance Provenance `json:"provenance"`
	Detail     string     `json:"detail,omitempty"`
}

// Group is the key an item deduplicates on for quorum purposes.
func (e Evidence) Group() string {
	if e.IndependenceGroup != "" {
		return e.IndependenceGroup
	}
	return e.Family
}

// Verdict is the outcome of adjudication.
//
// Suppressed is carried alongside Basis rather than discarded because "an operator's hold silenced
// this" and "no detector saw anything" are different states, and a system that renders them
// identically cannot explain itself.
type Verdict struct {
	Action     Action     `json:"action"`
	Strength   Strength   `json:"strength"`
	Basis      []Evidence `json:"basis,omitempty"`
	Suppressed []Evidence `json:"suppressed,omitempty"`

	// InferredFamilies is how many INDEPENDENT inferred groups agreed, recorded so a report can
	// show why a quorum was or was not reached rather than only what it concluded.
	InferredFamilies int `json:"inferred_families"`
}

// SessionRef identifies one session.
//
// 🔑 A VERDICT NAMES ITS MEMBERS. It does not carry a key from which members are recomputed later.
// "Every session of this hash" is a query whose answer grows after the verdict was reasoned about,
// and re-expanding it at release time is how ~24 real engaged in-app visitors were removed in a
// single pass. A device cohort is a POPULATION, not a device.
type SessionRef struct {
	SiteID    string `json:"site_id"`
	SessionID string `json:"session_id"`
}
