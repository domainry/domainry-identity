package auth

import (
	"testing"
	"time"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestAuthAssertionReplayIsClaimedOnceAndExpires(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceDialect())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identityStore)
	expiresAt := time.Now().UTC().Add(time.Minute)
	claimed, err := repository.ClaimAuthAssertion(t.Context(), "default", "saml", "https://idp.example.test", "assertion-1", expiresAt)
	if err != nil || !claimed {
		t.Fatalf("first claim=%v err=%v", claimed, err)
	}
	claimed, err = repository.ClaimAuthAssertion(t.Context(), "default", "saml", "https://idp.example.test", "assertion-1", expiresAt)
	if err != nil || claimed {
		t.Fatalf("replay claim=%v err=%v", claimed, err)
	}
	claimed, err = repository.ClaimAuthAssertion(t.Context(), "default", "saml", "https://idp.example.test", "expired", time.Now().UTC().Add(-time.Second))
	if err != nil || claimed {
		t.Fatalf("expired claim=%v err=%v", claimed, err)
	}
}
