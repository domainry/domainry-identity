package schema

import "testing"

func TestWorkspaceIdentityIndexNamesFitPortableIdentifierLimit(t *testing.T) {
	for table, expected := range map[string]string{
		"_identity_users": "uniq_identity_users_workspace_identity",
	} {
		name := workspaceIdentityIndexName(table)
		if name != expected || len(name) > 63 {
			t.Fatalf("table=%s index=%s length=%d", table, name, len(name))
		}
	}
	first := workspaceIdentityIndexName("_identity_installation_administrator_bootstrap_receipts")
	second := workspaceIdentityIndexName("_identity_installation_administrator_bootstrap_deliveries")
	if len(first) > 63 || len(second) > 63 || first == second {
		t.Fatalf("long bootstrap index names must be bounded and distinct: %s / %s", first, second)
	}
}
