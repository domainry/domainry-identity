package service_test

import (
	"context"
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type sqliteBusinessProfileResolver struct{}

func (sqliteBusinessProfileResolver) ResolveIdentityBusinessProfiles(context.Context, string, string) ([]identityservice.IdentityBusinessProfile, error) {
	return []identityservice.IdentityBusinessProfile{{BindingKey: "member", ProfileID: "member-1"}}, nil
}

func TestSystemManagedBusinessRoleReconciliationPersistsInSQLite(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertIdentityUser(t.Context(), "default", identitymodel.IdentityUser{ID: "user-1", Name: "Member", Email: "member@example.com", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertIdentityRole(t.Context(), "default", identitymodel.IdentityRole{ID: "member-role", Key: "member", Label: "Member", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	service, err := identityservice.NewIdentityDomainService(repository, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged,
	}})
	service.UseBusinessProfileResolver(sqliteBusinessProfileResolver{})
	if err := service.ReconcileSystemManagedBusinessRoles(t.Context(), "user-1"); err != nil {
		t.Fatal(err)
	}
	assignments, err := repository.ListIdentityUserRoleAssignments(t.Context(), "default", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].RoleID != "member-role" || assignments[0].BindingKey != "member" || assignments[0].ProfileID != "member-1" || assignments[0].Source != "profile_binding" {
		t.Fatalf("assignments=%+v", assignments)
	}
	// Re-login reconciliation is idempotent and keeps one durable assignment.
	if err := service.ReconcileSystemManagedBusinessRoles(t.Context(), "user-1"); err != nil {
		t.Fatal(err)
	}
	assignments, err = repository.ListIdentityUserRoleAssignments(t.Context(), "default", "user-1")
	if err != nil || len(assignments) != 1 {
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
}
