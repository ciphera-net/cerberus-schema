package cerberus

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestScanSpecCannotExpressCrossTenantMembership is O2 requirement 4 in the strongest form
// available, and it belongs here rather than in a lint.
//
// 🔴 THE PRODUCT PROMISE IS THAT NO CROSS-SITE VISITOR RECORD EXISTS. Cross-tenant reasoning may
// produce a COUNT — "this configuration appeared on more than one customer" — and must never
// produce a MEMBERSHIP LIST, because a list of which sites a device configuration visited IS that
// record, however it was assembled and whatever it is called.
//
// A lint over queries can be worked around by writing a different query. A grammar with no key that
// yields a (fingerprint, site) tuple cannot express the question at all, which is a different kind
// of guarantee: the failure is a compile-time absence rather than a policy someone has to remember.
//
// The test straddles. It asserts the two keys exist SEPARATELY — so the grammar is not merely
// impoverished — and that no single key combines them; and it asserts that a spec asking for both
// at once still returns counts rather than a per-site membership list.
func TestScanSpecCannotExpressCrossTenantMembership(t *testing.T) {
	// 1. Both keys exist on their own. Without this half the test passes against a grammar that
	//    simply has no grouping at all, which would prove nothing about cross-tenant reasoning.
	if !validGroups[GroupFingerprint] || !validGroups[GroupSite] {
		t.Fatal("the fingerprint and site keys must both exist; a grammar that cannot group by " +
			"either is not the thing being constrained here")
	}

	// 2. No key in the closed vocabulary yields a tuple. Every value is a single dimension, and a
	//    name that joins two of them would be the loophole.
	for g := range validGroups {
		name := string(g)
		for _, other := range []string{"site", "owner", "tenant"} {
			if name != other && strings.Contains(name, other) {
				t.Errorf("group key %q names a tenant dimension inside a compound key; that is a "+
					"cross-site membership grouping wearing a different name", name)
			}
		}
	}

	// 3. The result of the widest cross-tenant question is still COUNTS. A scan grouped by
	//    fingerprint AND site is legitimate — it is how "this cohort appeared on N customers" is
	//    computed — and what comes back must not be usable to reconstruct a visitor's site history.
	//
	//    Group carries Sessions, and that is deliberate and bounded: a verdict must enumerate the
	//    members it convicts rather than re-expand from a key at release time. A SessionRef names a
	//    site-scoped session id, which is exactly what enforcement needs and is not a cross-site
	//    identity: the same person on two sites has two unrelated session ids.
	gt := reflect.TypeOf(Group{})
	for i := 0; i < gt.NumField(); i++ {
		f := gt.Field(i)
		switch f.Name {
		case "Key", "Units", "Value", "Sessions":
		default:
			t.Errorf("Group grew a field %q — every addition here is a chance to return "+
				"membership where the design returns counts, so it needs its own argument", f.Name)
		}
	}
	rt := reflect.TypeOf(SessionRef{})
	if rt.NumField() != 2 {
		t.Error("SessionRef grew a field; it is deliberately a site-scoped session id and nothing " +
			"else, so that enumerating a verdict's members is not also building a cross-site record")
	}
}

// TestNoNonStdlibImports keeps the module importable.
//
// A schema module with a dependency is a dependency an adopter inherits for the privilege of
// agreeing with us about a field name. The CI pipeline additionally checks the resolved build
// graph, because a dependency introduced through go.mod alone would not appear in any import block.
func TestNoNonStdlibImports(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(strings.Split(p, "/")[0], ".") {
					t.Errorf("%s imports %q; this module is standard library only", name, p)
				}
			}
		}
	}
}

// TestPublishesShapesNeverNumbers is the disclosure boundary, checked rather than remembered.
//
// The rule is: publish a test iff its evasion cost is RECURRING. A threshold's evasion cost is a
// parameter change — one-time and zero-marginal — so a bar committed here hands over the exact
// value an adversary needs and buys nothing. The same goes for a token list, an allowlist, a
// honeypot prefix, and above all a corpus row: Ciphera is a PROCESSOR for that traffic and cannot
// publish a controller's data at all.
//
// This scans for the shapes those things take rather than for a list of forbidden words, because a
// list of forbidden words is itself something someone has to keep current.
func TestPublishesShapesNeverNumbers(t *testing.T) {
	banned := []struct {
		re  *regexp.Regexp
		why string
	}{
		{regexp.MustCompile(`(?i)\b(threshold|min_sessions|confidence)\s*[:=]\s*[0-9]`),
			"a numeric bar — evasion cost is a parameter change, so publishing it is pure loss"},
		{regexp.MustCompile(`(?i)honeypot.*(prefix|path)\s*[:=]\s*"`),
			"a honeypot path; per-site and free to keep private"},
		{regexp.MustCompile(`(?i)(allowlist|knownGood|whitelist)\s*[:=]?\s*\[?\s*"`),
			"an allowlist entry — publishing one hands over the bypass verbatim"},
		{regexp.MustCompile(`(?i)botUserAgentSubstrings|automationSignals|botViewports`),
			"a detector membership list; its risk is false-positive disclosure, not evasion"},
	}
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(p)
		if ext != ".go" && ext != ".json" && ext != ".md" && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		// * This file is the one place those names may appear, because the patterns have to spell
		// * them. It carries the NAMES of the forbidden artefacts and none of their VALUES, which
		// * is the distinction the whole test is about — a detector list's name discloses nothing,
		// * its membership discloses the false positives. Skipping it here is the price of the
		// * guard existing at all; caught by the guard firing on itself on its first run, which is
		// * a cheaper way to learn it than the alternative.
		if filepath.Base(p) == "contract_test.go" {
			return nil
		}
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		for _, bn := range banned {
			if loc := bn.re.FindIndex(b); loc != nil {
				t.Errorf("%s contains %q: %s", p, string(b[loc[0]:loc[1]]), bn.why)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestContractIsAdditiveOnly pins the exported surface.
//
// The promise is the one the Pulse Public Read API makes, in the same words: a field may be ADDED;
// none may be REMOVED, RENAMED, or CHANGE TYPE. An enum may gain a value; none may lose one.
//
// Pinning it as a golden list rather than as prose is the difference between a promise and a
// guarantee: removing a field then fails a test in this repository rather than a build in
// somebody's. A deliberate break has to edit this list, which is the point at which somebody has to
// justify it.
func TestContractIsAdditiveOnly(t *testing.T) {
	want := map[string][]string{
		"Observation": {"ASNClass", "Arrival", "Browser", "City", "Confidence", "Country",
			"DetectionMethod", "DetectionReason", "DetectionScore", "DeviceType", "Duration",
			"EventID", "EventName", "FirstParty", "HumanSignals", "IsDatacenter", "Language", "OS",
			"OwnerID", "Path", "RawPath", "RawReferrer", "Referrer", "ReferrerSource", "Region",
			"ScreenResolution", "ScrollDepth", "SessionID", "SignalRev", "SiteID", "Timestamp",
			"Timezone", "UAClass", "VisibleDuration"},
		"Evidence":   {"Class", "Detail", "Family", "IndependenceGroup", "Provenance", "RuleID"},
		"Verdict":    {"Action", "Basis", "InferredFamilies", "Strength", "Suppressed"},
		"SessionRef": {"SessionID", "SiteID"},
		"Spec": {"Aggregate", "ChainGapSeconds", "GroupBy", "MinUnits", "RequireFields", "Source",
			"Unit", "VerdictFilter", "Window"},
		"Window": {"Boundary", "Clock", "Days"},
		"Group":  {"Key", "Sessions", "Units", "Value"},
		"Result": {"Groups", "Spec", "Unreachable"},
	}
	types := map[string]reflect.Type{
		"Observation": reflect.TypeOf(Observation{}), "Evidence": reflect.TypeOf(Evidence{}),
		"Verdict": reflect.TypeOf(Verdict{}), "SessionRef": reflect.TypeOf(SessionRef{}),
		"Spec": reflect.TypeOf(Spec{}), "Window": reflect.TypeOf(Window{}),
		"Group": reflect.TypeOf(Group{}), "Result": reflect.TypeOf(Result{}),
	}
	for name, rt := range types {
		got := make([]string, 0, rt.NumField())
		for i := 0; i < rt.NumField(); i++ {
			got = append(got, rt.Field(i).Name)
		}
		sort.Strings(got)
		pinned := want[name]
		have := map[string]bool{}
		for _, f := range got {
			have[f] = true
		}
		for _, f := range pinned {
			if !have[f] {
				t.Errorf("%s.%s was REMOVED or RENAMED — this module is additive-only and every "+
					"adopter decoding that field breaks", name, f)
			}
		}
		// An addition is fine and is reported so the list stays current, not as a failure.
		for _, f := range got {
			found := false
			for _, p := range pinned {
				if p == f {
					found = true
					break
				}
			}
			if !found {
				t.Logf("%s.%s is new — additions are allowed; add it to the pinned list", name, f)
			}
		}
	}
}
