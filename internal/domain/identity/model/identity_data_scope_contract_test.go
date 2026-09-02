package identitymodel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalIdentityDataScope(t *testing.T) {
	tests := map[string]IdentityDataScope{"all_records": "all_records", "owned_records": "owned_records", "organization": "organization", "organization_and_children": "organization_and_children", "self_and_subordinates": "self_and_subordinates", "custom": "custom", "none": "none"}
	for input, want := range tests {
		if got, ok := CanonicalIdentityDataScope(input); !ok || got != want {
			t.Errorf("CanonicalIdentityDataScope(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	for _, rejected := range []string{"all", "owned", "own_records", "reporting_line", "organization_tree", "team", "warehouse"} {
		if _, ok := CanonicalIdentityDataScope(rejected); ok {
			t.Fatalf("legacy or unknown scope %q accepted", rejected)
		}
	}
}

func TestDataPermissionDoesNotOwnFunctionalOperationFlags(t *testing.T) {
	encoded, err := json.Marshal(DataPermission{ObjectKey: "customer", Scope: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"read"`) || strings.Contains(string(encoded), `"write"`) {
		t.Fatalf("data policy leaked functional authority: %s", encoded)
	}
	effective, err := json.Marshal(IdentityEffectiveDataAccess{ObjectKey: "customer", Allowed: true, Scope: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(effective), `"action"`) || strings.Contains(string(effective), `"read"`) || strings.Contains(string(effective), `"write"`) {
		t.Fatalf("effective data policy leaked functional authority: %s", effective)
	}
}
