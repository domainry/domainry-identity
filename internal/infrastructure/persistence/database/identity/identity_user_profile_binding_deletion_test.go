package identity_test

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityUserDeletionEnumeratesAndBlocksBoundProfiles(t *testing.T) {
	identityStore, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "bound-user.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	service, err := identityservice.NewIdentityDomainService(repository, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	user := identitymodel.IdentityUser{ID: "member-user", Name: "Member", Email: "member@example.com", Status: identitymodel.IdentityStatusActive}
	if err := service.UpsertUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO identity_profile_bindings
		(id, workspace_id, binding_key, object_key, profile_id, identity_user_id, status, version, created_at, updated_at)
		VALUES ('binding-1', 'default', 'member', 'member_profile', 'member-1', 'member-user', 'active', 1, 'now', 'now')`); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveUser(t.Context(), user.ID); apperror.CodeOf(err) != "backend.identity.user_profile_bindings_exist" {
		t.Fatalf("bound user deletion error=%v", err)
	}
	if _, found, err := repository.GetIdentityUser(t.Context(), "default", user.ID); err != nil || !found {
		t.Fatalf("blocked deletion removed account: found=%v err=%v", found, err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `UPDATE identity_profile_bindings SET identity_user_id = NULL, status = 'unlinked' WHERE id = 'binding-1'`); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveUser(t.Context(), user.ID); err != nil {
		t.Fatalf("unbound user deletion: %v", err)
	}
	if _, found, err := repository.GetIdentityUser(t.Context(), "default", user.ID); err != nil || found {
		t.Fatalf("deleted account found=%v err=%v", found, err)
	}
}
