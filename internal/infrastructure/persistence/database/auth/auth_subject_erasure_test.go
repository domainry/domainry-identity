package auth

import (
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestSubjectAuthenticationErasureSharesTransactionAndPreservesOtherUsers(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuthStoreWithKeyProvider(identity, store.SecretKeyProvider())
	now := time.Now().UTC()
	for _, item := range []struct{ workspace, user string }{{"workspace-primary", "subject"}, {"workspace-primary", "other"}, {"workspace-other", "subject"}} {
		key := item.workspace + "-" + item.user
		if err := auth.CreateAuthLoginTransaction(t.Context(), authmodel.AuthProviderChallenge{WorkspaceID: item.workspace, State: key, Provider: "totp", UserID: item.user, Phone: key, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}); err != nil {
			t.Fatal(err)
		}
		if err := auth.CreateAuthAuthorizationCode(t.Context(), authmodel.AuthAuthorizationCode{Code: key, WorkspaceID: item.workspace, ApplicationKey: "app", RedirectURL: "https://app.example.test/callback", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Session: authmodel.AuthSession{WorkspaceID: item.workspace, User: authmodel.AuthUser{ID: item.user, Email: item.user + "@example.test"}}}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string, expected int) {
		t.Helper()
		var count int
		// The table is a fixed test-owned identifier.
		if err := store.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != expected {
			t.Fatalf("%s rows=%d want=%d error=%v", table, count, expected, err)
		}
	}
	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EraseSubjectLoginArtifacts(t.Context(), tx, "workspace-primary", "subject", ""); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	count("_identity_auth_login_transactions", 3)
	count("_identity_auth_authorization_codes", 3)
	for i := 0; i < 2; i++ {
		tx, err := store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := auth.EraseSubjectLoginArtifacts(t.Context(), tx, "workspace-primary", "subject", ""); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		count("_identity_auth_login_transactions", 2)
		count("_identity_auth_authorization_codes", 2)
	}
}
