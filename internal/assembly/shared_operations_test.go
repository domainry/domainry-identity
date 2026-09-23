package assembly

import (
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
)

func installAndBindTestSharedOperations(t *testing.T, core *Core, store *database.IdentityStore) {
	t.Helper()
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS _operations (
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
	if _, err := store.DB().ExecContext(t.Context(), `CREATE UNIQUE INDEX IF NOT EXISTS uniq_runtime_operation_key ON _operations(workspace_id,system_purpose,owner,kind,idempotency_key)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS _operation_controls (
		system_purpose TEXT NOT NULL,
		control_kind TEXT NOT NULL,
		owner TEXT NOT NULL,
		state TEXT NOT NULL,
		reason TEXT NOT NULL,
		reference TEXT NOT NULL DEFAULT '',
		updated_by TEXT NOT NULL,
		revision BIGINT NOT NULL,
		updated_at TEXT NOT NULL,
		PRIMARY KEY(system_purpose,control_kind,owner)
	)`); err != nil {
		t.Fatal(err)
	}
	binding, ok := core.Binding.(identitysdk.OperationsPersistenceBinding)
	if !ok {
		t.Fatal("Identity binding does not expose shared Operations persistence binding")
	}
	if err := binding.BindOperationsPersistence(); err != nil {
		t.Fatal(err)
	}
}
