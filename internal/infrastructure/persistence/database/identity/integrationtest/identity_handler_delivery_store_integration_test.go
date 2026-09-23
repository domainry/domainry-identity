package identity_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestHandlerDeliveryStoreCommitsUserRolesProfileAndReceiptAsOneUnit(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "handler-delivery.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE employee_profile (
		workspace_id TEXT NOT NULL, id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, identity_user_id TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO employee_profile (workspace_id, id, created_at, updated_at) VALUES ('workspace-primary', 'employee-profile-1', 'now', 'now')`); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := identityStore.GetIdentityHandlerDeliveryReceipt(t.Context(), "workspace-primary", "delivery-1"); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound shared Operations error=%v", err)
	}
	bindSharedOperations(t, identityStore)
	if err := identityStore.UpsertIdentityRole(t.Context(), "workspace-primary", identitymodel.IdentityRole{ID: "employee-role", Key: "employee", Label: "Employee", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	mutation := identitymodel.IdentityHandlerDeliveryMutation{
		WorkspaceID: "workspace-primary", ActorID: "admin", IdempotencyKey: "delivery-1", RequestFingerprint: "fingerprint-1",
		Operation:       identitymodel.IdentityHandlerUserCreate,
		User:            identitymodel.IdentityUser{ID: "employee-1", Name: "Employee One", Email: "employee@example.test", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Version: 1, ReportingPath: "/employee-1"},
		Credential:      &identitymodel.IdentityCredential{UserID: "employee-1", PasswordHash: "bcrypt-hash", MustChangePassword: true},
		RoleAssignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "employee-1", RoleID: "employee-role", Source: "manual", Status: "active", GrantedBy: "admin"}},
		RoleKeys:        []string{"employee"},
		ProfileBinding: &identitymodel.IdentityProfileBindingMutation{
			WorkspaceID: "workspace-primary", BindingKey: "employee", ObjectKey: "employee_profile", ProfileID: "employee-profile-1",
			IdentityField: "identity_user_id", Operation: identitymodel.IdentityProfileBindingBind, IdentityUserID: "employee-1",
			ExpectedVersion: 0, IdempotencyKey: "delivery-1:profile", RequestFingerprint: "profile-fingerprint-1", ActorID: "admin",
		},
	}

	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.ExecuteIdentityHandlerDelivery(identitytransaction.WithExecutor(t.Context(), tx), mutation); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertHandlerDeliveryCounts(t, store, 0, 0, 0, 0, "")

	tx, err = store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := identityStore.ExecuteIdentityHandlerDelivery(identitytransaction.WithExecutor(t.Context(), tx), mutation)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if receipt.Result.User.ID != "employee-1" || receipt.Result.ProfileBinding == nil || receipt.Result.ProfileBinding.IdentityUserID != "employee-1" {
		_ = tx.Rollback()
		t.Fatalf("receipt=%+v", receipt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertHandlerDeliveryCounts(t, store, 1, 1, 1, 1, "employee-1")

	if err := identityStore.WithinIdentityTransaction(t.Context(), func(ctx context.Context) error {
		replayed, err := identityStore.ExecuteIdentityHandlerDelivery(ctx, mutation)
		if err != nil {
			return err
		}
		if !replayed.Result.Replayed || replayed.Result.DeliveryID != receipt.Result.DeliveryID {
			t.Fatalf("replayed=%+v", replayed)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	different := mutation
	different.RequestFingerprint = "different"
	if err := identityStore.WithinIdentityTransaction(t.Context(), func(ctx context.Context) error {
		_, err := identityStore.ExecuteIdentityHandlerDelivery(ctx, different)
		return err
	}); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("different replay error=%v", err)
	}
	assertHandlerDeliveryCounts(t, store, 1, 1, 1, 1, "employee-1")
	var legacyTableCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_handler_deliveries'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy handler delivery table count=%d err=%v", legacyTableCount, err)
	}
}

func assertHandlerDeliveryCounts(t *testing.T, store *IdentityStore, users, assignments, credentials, receipts int, profileUser string) {
	t.Helper()
	for table, expected := range map[string]int{
		"_identity_users": users, "_identity_user_role_assignments": assignments,
		"_identity_credentials": credentials,
	} {
		var actual int
		if err := store.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE workspace_id = 'workspace-primary'").Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("%s count=%d want=%d", table, actual, expected)
		}
	}
	var actualReceipts int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id = 'workspace-primary' AND owner = 'identity' AND kind = 'identity.handler_delivery'`).Scan(&actualReceipts); err != nil {
		t.Fatal(err)
	}
	if actualReceipts != receipts {
		t.Fatalf("handler delivery operation count=%d want=%d", actualReceipts, receipts)
	}
	var actualProfileUser string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COALESCE(identity_user_id, '') FROM employee_profile WHERE workspace_id = 'workspace-primary' AND id = 'employee-profile-1'`).Scan(&actualProfileUser); err != nil {
		t.Fatal(err)
	}
	if actualProfileUser != profileUser {
		t.Fatalf("profile user=%q want=%q", actualProfileUser, profileUser)
	}
}
