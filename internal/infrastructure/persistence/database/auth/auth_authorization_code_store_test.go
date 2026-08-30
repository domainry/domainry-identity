package auth

import (
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestAuthorizationCodeIsBoundAndConsumedExactlyOnce(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Now().UTC()
	value := authmodel.AuthAuthorizationCode{
		Code: "one-time-code", WorkspaceID: "default", ApplicationKey: "runtime-app",
		RedirectURL: "https://runtime.example.com/auth/callback", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Session: authmodel.AuthSession{WorkspaceID: "default", AccessToken: "access", RefreshToken: "refresh"},
	}
	if err := repository.CreateAuthAuthorizationCode(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, "other-app", value.RedirectURL, now); err != nil || consumed {
		t.Fatalf("wrong application consumed=%v err=%v", consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, "https://other.example.com/callback", now); err != nil || consumed {
		t.Fatalf("wrong redirect consumed=%v err=%v", consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), "workspace-b", value.Code, value.ApplicationKey, value.RedirectURL, now); err != nil || consumed {
		t.Fatalf("wrong workspace consumed=%v err=%v", consumed, err)
	}
	session, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, now)
	if err != nil || !consumed || session.RefreshToken != "refresh" {
		t.Fatalf("session=%#v consumed=%v err=%v", session, consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, now); err != nil || consumed {
		t.Fatalf("replay consumed=%v err=%v", consumed, err)
	}
	var persisted string
	if err := store.DB().QueryRowContext(t.Context(), "SELECT session_json FROM _identity_auth_authorization_codes").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted == "" || strings.Contains(persisted, "refresh") || strings.Contains(persisted, "access") {
		t.Fatalf("authorization session was not encrypted: %q", persisted)
	}
}
