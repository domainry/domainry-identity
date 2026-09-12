package identity_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestUserTableRejectsGlobalLoginDuplicatesOnCreateAndUpdate(t *testing.T) {
	database, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "global-login.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseContext(context.Background()) })
	if err := database.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), database.DB(), database.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	a := identitymodel.IdentityUser{ID: "user-a", Name: "Admin A", Email: " Admin@Example.Test ", Status: identitymodel.IdentityStatusActive}
	if err := store.UpsertIdentityUser(t.Context(), "workspace-a", a); err != nil {
		t.Fatal(err)
	}
	b := identitymodel.IdentityUser{ID: "user-b", Name: "Admin B", Email: "admin@example.test", Status: identitymodel.IdentityStatusActive}
	if err := store.CreateIdentityUser(t.Context(), "workspace-b", b); apperror.CodeOf(err) != "identity.login_name_conflict" {
		t.Fatalf("duplicate create: %v", err)
	}
	if err := store.UpsertIdentityUser(t.Context(), "workspace-b", b); apperror.CodeOf(err) != "identity.login_name_conflict" {
		t.Fatalf("duplicate upsert: %v", err)
	}
	b.Email = "unique@example.test"
	if err := store.UpsertIdentityUser(t.Context(), "workspace-b", b); err != nil {
		t.Fatal(err)
	}
	b.Email = "ADMIN@example.test"
	if err := store.UpsertIdentityUser(t.Context(), "workspace-b", b); apperror.CodeOf(err) != "identity.login_name_conflict" {
		t.Fatalf("duplicate update: %v", err)
	}
	unchanged, found, err := store.GetIdentityUser(t.Context(), "workspace-b", b.ID)
	if err != nil || !found || unchanged.Email != "unique@example.test" {
		t.Fatal("failed update changed B")
	}
	unchanged, found, err = store.GetIdentityUser(t.Context(), "workspace-a", a.ID)
	if err != nil || !found || unchanged.Name != a.Name {
		t.Fatal("failed upsert changed A")
	}
	var indexCount int
	if err := database.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_index_list('_identity_users') WHERE name='uniq_identity_users_login_name' AND "unique"=1`).Scan(&indexCount); err != nil || indexCount != 1 {
		t.Fatal("global unique index unavailable", err)
	}
}
