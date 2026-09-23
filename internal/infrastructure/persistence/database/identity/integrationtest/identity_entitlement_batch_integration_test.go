package identity_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func bindSharedOperations(t *testing.T, store *identitypersistence.SQLIdentityStore) {
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
	store.BindOperationsPersistence()
}

func TestEntitlementBatchUsesOneTransactionAndStableIdempotencyReceipt(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "entitlement-batch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace-primary", "batch-1"); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound shared Operations error=%v", err)
	}
	bindSharedOperations(t, store)
	mutation := identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID: "workspace-primary", ActorID: "grant-admin", IdempotencyKey: "batch-1", RequestFingerprint: "fingerprint-1",
		Items: []identitymodel.IdentityEntitlementBatchItem{
			{Operation: "grant", UserID: "target", RoleID: "role-1"},
			{Operation: "grant", UserID: "target", RoleID: "role-2"},
		},
		Assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "target", RoleID: "role-1", Source: "manual", Status: "active", GrantedBy: "grant-admin"},
			{UserID: "target", RoleID: "role-2", Source: "manual", Status: "active", GrantedBy: "grant-admin"},
		},
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER fail_second_batch_entitlement BEFORE INSERT ON _identity_user_role_assignments
		WHEN NEW.role_id = 'role-2' BEGIN SELECT RAISE(ABORT, 'injected second entitlement failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyIdentityEntitlementBatch(t.Context(), mutation); err == nil {
		t.Fatal("injected second entitlement failure was ignored")
	}
	assignments, err := store.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "target")
	if err != nil || len(assignments) != 0 {
		t.Fatalf("partial batch persisted=%#v err=%v", assignments, err)
	}
	if receipt, found, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace-primary", "batch-1"); err != nil || found {
		t.Fatalf("failed batch wrote receipt=%#v found=%v err=%v", receipt, found, err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER fail_second_batch_entitlement`); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ApplyIdentityEntitlementBatch(t.Context(), mutation)
	if err != nil || receipt.Replayed {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	replay, err := store.ApplyIdentityEntitlementBatch(t.Context(), mutation)
	if err != nil || !replay.Replayed || replay.ID != receipt.ID {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	reused := mutation
	reused.RequestFingerprint = "fingerprint-2"
	if _, err := store.ApplyIdentityEntitlementBatch(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("reused key error=%v", err)
	}
	assignments, err = store.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "target")
	if err != nil || len(assignments) != 2 {
		t.Fatalf("atomic batch assignments=%#v err=%v", assignments, err)
	}
	var operationCount, legacyTableCount int
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id='workspace-primary' AND owner='identity' AND kind='identity.entitlement_batch' AND idempotency_key='batch-1' AND status='succeeded'`).Scan(&operationCount); err != nil || operationCount != 1 {
		t.Fatalf("shared entitlement operation count=%d err=%v", operationCount, err)
	}
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_entitlement_batch_receipts'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy entitlement receipt table count=%d err=%v", legacyTableCount, err)
	}
}

func TestScopedEntitlementBatchRejectsOneForeignTargetWithoutPartialWrites(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "entitlement-batch-scope.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	bindSharedOperations(t, store)
	for _, user := range []identitymodel.IdentityUser{
		{ID: "sales-user", Name: "Sales", Email: "sales@example.com", OrgID: "sales", Status: identitymodel.IdentityStatusActive},
		{ID: "finance-user", Name: "Finance", Email: "finance@example.com", OrgID: "finance", Status: identitymodel.IdentityStatusActive},
	} {
		if err := store.UpsertIdentityUser(t.Context(), "workspace-primary", user); err != nil {
			t.Fatal(err)
		}
	}
	mutation := identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID: "workspace-primary", ActorID: "admin", IdempotencyKey: "scoped-batch", RequestFingerprint: "scoped-fingerprint",
		Items: []identitymodel.IdentityEntitlementBatchItem{
			{Operation: "grant", UserID: "sales-user", RoleID: "role"},
			{Operation: "grant", UserID: "finance-user", RoleID: "role"},
		},
		Assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "sales-user", RoleID: "role", Status: "active"},
			{UserID: "finance-user", RoleID: "role", Status: "active"},
		},
	}
	if _, allowed, err := store.ApplyIdentityEntitlementBatchWithinDataScope(t.Context(), mutation, identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"sales"}}); err != nil || allowed {
		t.Fatalf("foreign-target batch allowed=%t err=%v", allowed, err)
	}
	assignments, err := store.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "")
	if err != nil || len(assignments) != 0 {
		t.Fatalf("foreign-target batch left partial assignments=%#v err=%v", assignments, err)
	}
	if _, found, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace-primary", "scoped-batch"); err != nil || found {
		t.Fatalf("foreign-target batch wrote receipt found=%t err=%v", found, err)
	}
}
