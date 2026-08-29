package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityRoleAssignmentFactsRoundTrip(t *testing.T) {
	identityStore, err := OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "role-assignment-facts.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceDialect())
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := "2027-01-01T00:00:00Z"
	want := identitymodel.IdentityUserRoleAssignment{
		UserID:             "user-1",
		RoleID:             "role-1",
		WorkforceProfileID: "workforce-1",
		BindingKey:         "member",
		ProfileID:          "member-1",
		Source:             "governance_request",
		Status:             "revoked",
		ValidFrom:          "2026-01-01T00:00:00Z",
		ValidUntil:         expiresAt,
		GrantedBy:          "grantor-1",
		GrantReason:        "approved request",
		RevokedBy:          "reviewer-1",
		RevokedAt:          "2026-06-01T00:00:00Z",
		RevokeReason:       "access review",
		ExpiresAt:          &expiresAt,
		CreatedAt:          "2026-01-01T00:00:00Z",
	}
	if err := repository.AssignIdentityUserRole(t.Context(), "default", want); err != nil {
		t.Fatal(err)
	}
	got, err := repository.ListIdentityUserRoleAssignments(t.Context(), "default", want.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("assignments=%+v", got)
	}
	actual := got[0]
	if actual.UserID != want.UserID || actual.RoleID != want.RoleID ||
		actual.WorkforceProfileID != want.WorkforceProfileID ||
		actual.BindingKey != want.BindingKey || actual.ProfileID != want.ProfileID ||
		actual.Source != want.Source || actual.Status != want.Status ||
		actual.ValidFrom != want.ValidFrom || actual.ValidUntil != want.ValidUntil ||
		actual.GrantedBy != want.GrantedBy || actual.GrantReason != want.GrantReason ||
		actual.RevokedBy != want.RevokedBy || actual.RevokedAt != want.RevokedAt ||
		actual.RevokeReason != want.RevokeReason || actual.ExpiresAt == nil ||
		*actual.ExpiresAt != *want.ExpiresAt || actual.CreatedAt != want.CreatedAt ||
		actual.UpdatedAt == "" {
		t.Fatalf("assignment facts did not round-trip:\nwant=%+v\ngot=%+v", want, actual)
	}
}
