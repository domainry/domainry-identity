package identity_test

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

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
	mutation := identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID: "default", ActorID: "grant-admin", IdempotencyKey: "batch-1", RequestFingerprint: "fingerprint-1",
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
	assignments, err := store.ListIdentityUserRoleAssignments(t.Context(), "default", "target")
	if err != nil || len(assignments) != 0 {
		t.Fatalf("partial batch persisted=%#v err=%v", assignments, err)
	}
	if receipt, found, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "default", "batch-1"); err != nil || found {
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
	assignments, err = store.ListIdentityUserRoleAssignments(t.Context(), "default", "target")
	if err != nil || len(assignments) != 2 {
		t.Fatalf("atomic batch assignments=%#v err=%v", assignments, err)
	}
}
