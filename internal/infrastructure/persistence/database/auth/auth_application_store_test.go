package auth

import (
	"fmt"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

func TestAuthApplicationStoreBatchesAndPreservesAdministratorStatus(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity)
	registrations := make([]authmodel.AuthApplicationRegistration, 300)
	for index := range registrations {
		registrations[index] = authmodel.AuthApplicationRegistration{
			WorkspaceID: "workspace-primary", ApplicationKey: fmt.Sprintf("application-%03d", index),
			RedirectURLs: []string{fmt.Sprintf("https://application-%03d.example.test/callback", index)},
		}
	}
	if err := repository.UpsertAuthApplications(t.Context(), "workspace-primary", registrations); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_applications WHERE workspace_id = ?`, "workspace-primary").Scan(&count); err != nil || count != len(registrations) {
		t.Fatalf("application count=%d want=%d err=%v", count, len(registrations), err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `UPDATE _identity_applications SET status = 'disabled' WHERE workspace_id = ? AND application_key = ?`, "workspace-primary", "application-000"); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertAuthApplications(t.Context(), "workspace-primary", []authmodel.AuthApplicationRegistration{{
		WorkspaceID: "workspace-primary", ApplicationKey: "application-000", RedirectURLs: []string{"https://changed.example.test/callback"},
	}}); err != nil {
		t.Fatal(err)
	}
	registration, found, err := repository.GetAuthApplication(t.Context(), "workspace-primary", "application-000")
	if err != nil || !found || registration.Status != authmodel.AuthApplicationDisabled || len(registration.RedirectURLs) != 1 || registration.RedirectURLs[0] != "https://changed.example.test/callback" {
		t.Fatalf("preserved application=%+v found=%t err=%v", registration, found, err)
	}
	allowed, err := repository.AuthorizationRedirectRegistered(t.Context(), "workspace-primary", "application-000", "https://changed.example.test/callback")
	if err != nil || allowed {
		t.Fatalf("disabled application redirect allowed=%t err=%v", allowed, err)
	}
}

func TestAuthApplicationStoreValidatesWholeBatchBeforeWriting(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity)
	err = repository.UpsertAuthApplications(t.Context(), "workspace-primary", []authmodel.AuthApplicationRegistration{
		{WorkspaceID: "workspace-primary", ApplicationKey: "must-not-write"},
		{WorkspaceID: "other-workspace", ApplicationKey: "invalid-scope"},
	})
	if err == nil {
		t.Fatal("cross-workspace registration batch was accepted")
	}
	if _, found, lookupErr := repository.GetAuthApplication(t.Context(), "workspace-primary", "must-not-write"); lookupErr != nil || found {
		t.Fatalf("partially written batch found=%t err=%v", found, lookupErr)
	}
}

func TestAuthApplicationStoreJoinsHostTransaction(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity)
	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	txContext := transaction.WithExecutor(t.Context(), tx)
	if err := repository.UpsertAuthApplications(txContext, "workspace-primary", []authmodel.AuthApplicationRegistration{{WorkspaceID: "workspace-primary", ApplicationKey: "rolled-back"}}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, found, err := repository.GetAuthApplication(txContext, "workspace-primary", "rolled-back"); err != nil || !found {
		_ = tx.Rollback()
		t.Fatalf("transaction-local application found=%t err=%v", found, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repository.GetAuthApplication(t.Context(), "workspace-primary", "rolled-back"); err != nil || found {
		t.Fatalf("rolled-back application found=%t err=%v", found, err)
	}
}
