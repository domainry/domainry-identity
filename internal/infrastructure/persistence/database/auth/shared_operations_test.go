package auth

import (
	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func installAndBindAuthTestSharedOperations(t *testing.T, identity *identitypersistence.SQLIdentityStore) {
	t.Helper()
	if _, err := identity.DB().ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS _operations (
		id TEXT PRIMARY KEY,
		workspace_id TEXT NOT NULL,
		system_purpose TEXT NOT NULL DEFAULT '',
		owner TEXT NOT NULL,
		kind TEXT NOT NULL,
		action_key TEXT NOT NULL,
		parent_id TEXT NOT NULL DEFAULT '',
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL DEFAULT '',
		idempotency_key TEXT NOT NULL,
		request_fingerprint TEXT NOT NULL,
		requested_by TEXT NOT NULL,
		reason TEXT NOT NULL,
		reference TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL,
		status_url TEXT NOT NULL,
		result_json TEXT NOT NULL,
		metadata_json TEXT NOT NULL,
		error_code TEXT NOT NULL DEFAULT '',
		failure_class TEXT NOT NULL DEFAULT '',
		next_action TEXT NOT NULL DEFAULT '',
		related_ids_json TEXT NOT NULL,
		correlation TEXT NOT NULL DEFAULT '',
		evidence_json TEXT NOT NULL,
		lease_owner TEXT NOT NULL DEFAULT '',
		lease_expires_at TEXT NOT NULL DEFAULT '',
		fencing_token BIGINT NOT NULL DEFAULT 0,
		expires_at TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		started_at TEXT NOT NULL DEFAULT '',
		finished_at TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.DB().ExecContext(t.Context(), `CREATE UNIQUE INDEX IF NOT EXISTS uniq_runtime_operation_key ON _operations(workspace_id,system_purpose,owner,kind,idempotency_key)`); err != nil {
		t.Fatal(err)
	}
	identity.BindOperationsPersistence()
}
