package cerberus

import (
	"encoding/json"
	"os"
	"testing"
)

// TestPackSchemaEnumsMatchTheGoGrammar is the guard against the two halves drifting.
//
// The JSON schema and the Go types describe the SAME closed grammar in two languages, which is
// exactly the arrangement that comes apart quietly: a value added to one is not a compile error in
// the other, and the symptom is a pack that validates and then fails to load, or worse, one that
// loads with a value the engine silently ignores.
//
// Two tables of the same enum is one more than can be kept in agreement, so this compares them.
func TestPackSchemaEnumsMatchTheGoGrammar(t *testing.T) {
	b, err := os.ReadFile("pack.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("pack.schema.json is not valid JSON: %v", err)
	}

	scan := doc["$defs"].(map[string]any)["scan"].(map[string]any)["properties"].(map[string]any)
	enumOf := func(path ...string) []string {
		var node any = scan
		for _, p := range path {
			node = node.(map[string]any)[p]
		}
		var out []string
		for _, v := range node.([]any) {
			out = append(out, v.(string))
		}
		return out
	}

	cases := []struct {
		name  string
		json  []string
		valid map[string]bool
	}{
		{"group_by", enumOf("group_by", "items", "enum"), stringSet(validGroups)},
		{"aggregate", enumOf("aggregate", "enum"), stringSet(validAggregates)},
		{"require_fields", enumOf("require_fields", "items", "enum"), stringSet(validFields)},
	}
	for _, c := range cases {
		if len(c.json) != len(c.valid) {
			t.Errorf("%s: schema has %d values, Go has %d — one side gained a value the other has "+
				"never heard of, which is a pack that validates and then does not load",
				c.name, len(c.json), len(c.valid))
		}
		for _, v := range c.json {
			if !c.valid[v] {
				t.Errorf("%s: schema admits %q, the Go grammar rejects it", c.name, v)
			}
		}
	}

	// The class enum is on the detector rather than on the scan, and must match verdict.go.
	det := doc["$defs"].(map[string]any)["detector"].(map[string]any)["properties"].(map[string]any)
	goClasses := map[string]bool{
		string(ClassDeclared): true, string(ClassConstructive): true, string(ClassPhysical): true,
		string(ClassPopulation): true, string(ClassCrossTenant): true, string(ClassCircumstance): true,
	}
	var schemaClasses []string
	for _, v := range det["class"].(map[string]any)["enum"].([]any) {
		schemaClasses = append(schemaClasses, v.(string))
	}
	if len(schemaClasses) != len(goClasses) {
		t.Errorf("class: schema has %d values, Go has %d", len(schemaClasses), len(goClasses))
	}
	for _, v := range schemaClasses {
		if !goClasses[v] {
			t.Errorf("class: schema admits %q, which is not a Class in verdict.go", v)
		}
	}
}

func stringSet[T ~string](m map[T]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[string(k)] = true
	}
	return out
}
