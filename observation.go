package cerberus

import "time"

// ArrivalState records which side of a previous decision an observation landed on.
//
// 🔑 A CORPUS CARRYING ONLY THE ACCEPTED SIDE IS NOT A CORPUS. A candidate rule replayed against
// accepted traffic alone never sees the sessions the incumbent already removed, and then reports
// "no false positives" — truthfully, and uselessly, because it convicted nothing that was there to
// convict. On the corpus this schema was extracted from, 24.1% of observations exist only on the
// quarantined side.
type ArrivalState string

const (
	ArrivalAccepted    ArrivalState = "accepted"
	ArrivalQuarantined ArrivalState = "quarantined"
)

// Observation is one event as it ARRIVED, before any verdict was applied.
//
// Every optional telemetry field is a pointer and there is deliberately no IsPresent helper. The
// absence of a telemetry field is not behaviour until you know how often the platform emits it at
// all: scroll emission measured between 11.3% (Chrome/Linux) and 81.9% (Facebook/Android) among
// sessions that all reported duration normally. A rule reading absence as intent convicts the
// platforms that do not emit.
//
// 🔴 THERE IS NO RAW USER-AGENT FIELD AND THERE WILL NOT BE ONE. UAClass is a derived enum; the
// header itself is classified at ingest and dropped. A schema that carried the raw string would
// make every adopter's corpus a re-identification surface for no detection benefit.
type Observation struct {
	// --- identity -----------------------------------------------------------------------------
	//
	// OwnerID is the TENANT, and it is separate from SiteID because cross-tenant reasoning is
	// meaningless without it. FirstParty marks the operator's own properties: counting them as
	// customers is what made a cross-tenant bar reachable in one measurement and unreachable in
	// production, with nothing saying so.
	SiteID     string `json:"site_id"`
	OwnerID    string `json:"owner_id"`
	FirstParty bool   `json:"first_party"`
	SessionID  string `json:"session_id"`
	EventID    string `json:"event_id"`

	Timestamp time.Time    `json:"timestamp"`
	Arrival   ArrivalState `json:"arrival"`
	EventName string       `json:"event_name"`

	// --- device cohort ------------------------------------------------------------------------
	//
	// ⚠️ ScreenResolution is the CSS VIEWPORT, not the display. 412x823 is a common real Android
	// portrait and 430x932 a real iPhone Pro Max. Convicting on bare geometry has a measured
	// history of taking real mobile users.
	Browser          *string `json:"browser,omitempty"`
	OS               *string `json:"os,omitempty"`
	DeviceType       *string `json:"device_type,omitempty"`
	Language         *string `json:"language,omitempty"`
	ScreenResolution *string `json:"screen_resolution,omitempty"`
	Timezone         *string `json:"timezone,omitempty"`

	Country *string `json:"country,omitempty"`
	City    *string `json:"city,omitempty"`
	Region  *string `json:"region,omitempty"`

	Path        *string `json:"path,omitempty"`
	RawPath     *string `json:"raw_path,omitempty"`
	Referrer    *string `json:"referrer,omitempty"`
	RawReferrer *string `json:"raw_referrer,omitempty"`

	// --- engagement ---------------------------------------------------------------------------
	//
	// 🔴 CLIENT-CONTROLLED IN BOTH DIRECTIONS, AND THE ONLY FIELDS HERE THAT HAVE BEEN FORGED IN
	// PRACTICE. A known actor manufactured these on 348 sessions to buy exemption from every
	// delayed rule, and stopped emitting them entirely the day a forgery detector shipped. Never
	// let a rule REVOKE on these alone: a client-asserted rebuttal is an attacker-supplied
	// acquittal.
	Duration        *float64 `json:"duration,omitempty"`
	VisibleDuration *float64 `json:"visible_duration,omitempty"`
	ScrollDepth     *int16   `json:"scroll_depth,omitempty"`

	// --- derived signals ----------------------------------------------------------------------
	//
	// Derived server-side from data that is not retained. SignalRev is the version of the
	// derivation, so a corpus spanning a change to it is legible rather than silently mixed.
	UAClass        *string `json:"ua_class,omitempty"`
	ASNClass       *string `json:"asn_class,omitempty"`
	HumanSignals   *int    `json:"human_signals,omitempty"`
	ReferrerSource *string `json:"referrer_source,omitempty"`
	SignalRev      *int    `json:"signal_rev,omitempty"`

	// --- what a previous detector decided -----------------------------------------------------
	//
	// Carried so a candidate can be compared against what the incumbent saw, and pointers because
	// on a real corpus they are mostly absent.
	DetectionScore  *int16  `json:"detection_score,omitempty"`
	IsDatacenter    *bool   `json:"is_datacenter,omitempty"`
	DetectionReason *string `json:"detection_reason,omitempty"`
	DetectionMethod *string `json:"detection_method,omitempty"`
	Confidence      *string `json:"confidence_score,omitempty"`
}

// DeviceCohort is the key most population rules group on: browser, OS, device type, language and
// viewport — and deliberately NOT timezone.
//
// 🔑 EXCLUDING TIMEZONE IS THE POINT, not an omission. An actor that rotates its declared zone
// splits into one key per zone under any grouping that includes it, and then no per-key rule
// reaches its threshold. Collapsing the zone out is the one move that technique cannot answer,
// because rotating IS the technique. Rules that need the declared clock ask for Fingerprint.
func (o *Observation) DeviceCohort() string {
	return deref(o.Browser) + "|" + deref(o.OS) + "|" + deref(o.DeviceType) + "|" +
		deref(o.Language) + "|" + deref(o.ScreenResolution)
}

// Fingerprint is DeviceCohort plus the declared timezone.
func (o *Observation) Fingerprint() string {
	return o.DeviceCohort() + "|" + deref(o.Timezone)
}

// Engaged is the engagement predicate: any of duration, visible duration or scroll depth present.
//
// ⚠️ EVERY RULE AND EVERY MEASUREMENT MUST USE THIS ONE. A scroll-only definition gives a 62.6%
// baseline where this gives 89.0% on the same corpus, and mixing the two propagated a single error
// through six findings of one audit report. Two definitions of "engaged" is one more than can be
// kept in agreement.
func (o *Observation) Engaged() bool {
	return o.Duration != nil || o.VisibleDuration != nil || o.ScrollDepth != nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
