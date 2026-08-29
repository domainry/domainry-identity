package identity_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestRoleRequestDecisionIsAtomicAcrossEveryEntitlementAndRequestState(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "role-request-atomic.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceDialect())
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.CreateIdentityRoleRequest(t.Context(), "default", identitymodel.IdentityRoleRequest{
		ID: "request-1", UserID: "target", RequestedBy: "maker", RoleIDs: []string{"role-1", "role-2", "role-3"}, Status: "pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER fail_second_entitlement BEFORE INSERT ON identity_user_role_assignments
		WHEN NEW.role_id = 'role-2' BEGIN SELECT RAISE(ABORT, 'injected second entitlement failure'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	request.Status, request.ReviewedBy, request.ReviewedAt, request.UpdatedAt = "approved", "checker", now, now
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "target", RoleID: "role-1", Source: "governance_request", Status: "active", GrantedBy: "checker"},
		{UserID: "target", RoleID: "role-2", Source: "governance_request", Status: "active", GrantedBy: "checker"},
		{UserID: "target", RoleID: "role-3", Source: "governance_request", Status: "active", GrantedBy: "checker"},
	}
	if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "default", request, assignments, "pending"); err == nil {
		t.Fatal("injected second entitlement failure was ignored")
	}
	persisted, err := store.ListIdentityUserRoleAssignments(t.Context(), "default", "target")
	if err != nil || len(persisted) != 0 {
		t.Fatalf("partial entitlements persisted=%#v err=%v", persisted, err)
	}
	requests, err := store.ListIdentityRoleRequests(t.Context(), "default", "", "")
	if err != nil || len(requests) != 1 || requests[0].Status != "pending" {
		t.Fatalf("request left explainable state=%#v err=%v", requests, err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER fail_second_entitlement`); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "default", request, assignments, "pending"); err != nil {
		t.Fatal(err)
	}
	persisted, err = store.ListIdentityUserRoleAssignments(t.Context(), "default", "target")
	if err != nil || len(persisted) != 3 {
		t.Fatalf("atomic entitlements=%#v err=%v", persisted, err)
	}
	if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "default", request, assignments, "pending"); apperror.CodeOf(err) != "backend.identity.role_request_concurrent_decision" {
		t.Fatalf("concurrent decision error=%v", err)
	}
}
