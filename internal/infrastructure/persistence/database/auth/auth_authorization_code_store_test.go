package auth

import (
	"crypto/sha256"
	"encoding/base64"
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
		Code: "one-time-code", WorkspaceID: "workspace-primary", ApplicationKey: "runtime-app",
		RedirectURL: "https://runtime.example.com/auth/callback", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Session: authmodel.AuthSession{WorkspaceID: "workspace-primary", AccessToken: "access", RefreshToken: "refresh"},
	}
	if err := repository.CreateAuthAuthorizationCode(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if workspaceID, found, err := repository.AuthorizationCodeWorkspace(t.Context(), value.Code, value.ApplicationKey, value.RedirectURL, now); err != nil || !found || workspaceID != value.WorkspaceID {
		t.Fatalf("authorization code workspace=%q found=%v err=%v", workspaceID, found, err)
	}
	for _, mismatch := range []struct {
		applicationKey string
		redirectURL    string
	}{{"other-app", value.RedirectURL}, {value.ApplicationKey, "https://other.example.com/callback"}} {
		if workspaceID, found, err := repository.AuthorizationCodeWorkspace(t.Context(), value.Code, mismatch.applicationKey, mismatch.redirectURL, now); err != nil || found || workspaceID != "" {
			t.Fatalf("mismatched authorization code workspace=%q found=%v err=%v", workspaceID, found, err)
		}
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, "other-app", value.RedirectURL, "", now); err != nil || consumed {
		t.Fatalf("wrong application consumed=%v err=%v", consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, "https://other.example.com/callback", "", now); err != nil || consumed {
		t.Fatalf("wrong redirect consumed=%v err=%v", consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), "workspace-b", value.Code, value.ApplicationKey, value.RedirectURL, "", now); err != nil || consumed {
		t.Fatalf("wrong workspace consumed=%v err=%v", consumed, err)
	}
	session, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, "", now)
	if err != nil || !consumed || session.RefreshToken != "refresh" {
		t.Fatalf("session=%#v consumed=%v err=%v", session, consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, "", now); err != nil || consumed {
		t.Fatalf("replay consumed=%v err=%v", consumed, err)
	}
	if workspaceID, found, err := repository.AuthorizationCodeWorkspace(t.Context(), value.Code, value.ApplicationKey, value.RedirectURL, now); err != nil || found || workspaceID != "" {
		t.Fatalf("consumed authorization code workspace=%q found=%v err=%v", workspaceID, found, err)
	}
	var persisted string
	if err := store.DB().QueryRowContext(t.Context(), "SELECT session_json FROM _identity_auth_authorization_codes").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted == "" || strings.Contains(persisted, "refresh") || strings.Contains(persisted, "access") {
		t.Fatalf("authorization session was not encrypted: %q", persisted)
	}
}

func TestAuthorizationCodePKCEFailureDoesNotConsumeCode(t *testing.T) {
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
	verifier := "knowledge-browser-pkce-verifier-0123456789abcdef"
	digest := sha256.Sum256([]byte(verifier))
	value := authmodel.AuthAuthorizationCode{
		Code:                "pkce-one-time-code",
		WorkspaceID:         "workspace-primary",
		ApplicationKey:      "verdent-knowledge",
		RedirectURL:         "http://127.0.0.1:8080/auth/callback",
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(digest[:]),
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute).Format(time.RFC3339Nano),
		Session:             authmodel.AuthSession{WorkspaceID: "workspace-primary", AccessToken: "access", RefreshToken: "refresh"},
	}
	if err := repository.CreateAuthAuthorizationCode(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, "wrong-verifier-that-is-long-enough-0123456789abcdef", now); err != nil || consumed {
		t.Fatalf("wrong verifier consumed=%v err=%v", consumed, err)
	}
	session, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, verifier, now)
	if err != nil || !consumed || session.RefreshToken != "refresh" {
		t.Fatalf("session=%#v consumed=%v err=%v", session, consumed, err)
	}
	if _, consumed, err := repository.ConsumeAuthAuthorizationCode(t.Context(), value.WorkspaceID, value.Code, value.ApplicationKey, value.RedirectURL, verifier, now); err != nil || consumed {
		t.Fatalf("replay consumed=%v err=%v", consumed, err)
	}
}
