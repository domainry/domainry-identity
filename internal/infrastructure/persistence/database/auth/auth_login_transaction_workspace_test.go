package auth

import (
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestFederatedLoginWorkspaceResolvesWithoutConsumingTransaction(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceDialect())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID: "default", Provider: "oidc", State: "opaque-state",
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	if err := repository.CreateAuthLoginTransaction(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	if workspaceID, found, err := repository.FederatedLoginWorkspace(t.Context(), "oidc", challenge.State, now); err != nil || !found || workspaceID != "default" {
		t.Fatalf("workspace=%q found=%v err=%v", workspaceID, found, err)
	}
	if _, found, err := repository.ConsumeAuthLoginTransaction(t.Context(), "workspace-b", "oidc", challenge.State, now); err != nil || found {
		t.Fatalf("cross-workspace consume found=%v err=%v", found, err)
	}
	if _, found, err := repository.ConsumeAuthLoginTransaction(t.Context(), "default", "oidc", challenge.State, now); err != nil || !found {
		t.Fatalf("consume found=%v err=%v", found, err)
	}
	if workspaceID, found, err := repository.FederatedLoginWorkspace(t.Context(), "oidc", challenge.State, now); err != nil || found || workspaceID != "" {
		t.Fatalf("consumed workspace=%q found=%v err=%v", workspaceID, found, err)
	}
}
