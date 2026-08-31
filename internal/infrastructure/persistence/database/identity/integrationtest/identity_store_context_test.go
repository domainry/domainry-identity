package identity_test

import (
	"context"
	"errors"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"path/filepath"
	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSQLIdentityStoreStopsCanceledUserWriteBeforeCacheMutation(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-context.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	err = identity.UpsertIdentityUser(canceled, "workspace-primary", identitymodel.IdentityUser{ID: "cancelled-user", Name: "Cancelled", Email: "cancelled@example.com"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if _, found, err := identity.GetIdentityUser(t.Context(), "workspace-primary", "cancelled-user"); err != nil || found {
		t.Fatalf("cancelled write mutated identity cache: found=%v err=%v", found, err)
	}
}
