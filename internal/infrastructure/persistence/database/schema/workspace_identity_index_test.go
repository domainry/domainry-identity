package schema

import "testing"

func TestWorkspaceIdentityIndexNamesFitPortableIdentifierLimit(t *testing.T) {
	for table, expected := range map[string]string{
		"identity_workforce_legacy_migration_receipts": "uniq_identity_workforce_legacy_receipt_workspace",
		"identity_workforce_transfer_batch_receipts":   "uniq_identity_workforce_transfer_receipt_workspace",
		"identity_users": "uniq_identity_users_workspace_identity",
	} {
		name := workspaceIdentityIndexName(table)
		if name != expected || len(name) > 63 {
			t.Fatalf("table=%s index=%s length=%d", table, name, len(name))
		}
	}
}
