package identitymodel

import "testing"

func TestCanonicalIdentityDataScope(t *testing.T) {
	tests := map[string]IdentityDataScope{"all_records": "all_records", "owned_records": "owned_records", "department_and_children": "department_and_children", "subordinates": "subordinates", "custom": "custom", "none": "none"}
	for input, want := range tests {
		if got, ok := CanonicalIdentityDataScope(input); !ok || got != want {
			t.Errorf("CanonicalIdentityDataScope(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	for _, rejected := range []string{"all", "owned", "own_records", "self_and_subordinates", "department_tree", "warehouse"} {
		if _, ok := CanonicalIdentityDataScope(rejected); ok {
			t.Fatalf("legacy or unknown scope %q accepted", rejected)
		}
	}
}
