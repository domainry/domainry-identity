package module_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodule "github.com/domainry/domainry-identity/module"
	_ "modernc.org/sqlite"
)

var errInjectedWorkspaceProvisionFailure = errors.New("injected workspace provisioning failure")

type exactWorkspaceProvisionFailureInjector struct{ target string }

func (injector exactWorkspaceProvisionFailureInjector) InjectWorkspaceProvisionFailure(point string) error {
	if point == injector.target {
		return errInjectedWorkspaceProvisionFailure
	}
	return nil
}

func TestBootstrapBindingCreatesNoTenantBeforeHostAtomicProvision(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "identity-bootstrap.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	factory := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath})
	bootstrap, err := factory.OpenBootstrapWithDatabase(t.Context(), "runtime", identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: &testEmbeddedMigrationRegistrar{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bootstrap.Close(t.Context()) })
	for _, table := range []string{"_identity_users", "_identity_roles", "_identity_user_role_assignments", "_identity_credentials", "_identity_permissions"} {
		assertAllIdentityRows(t, db, table, 0)
	}
	failed, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "default", AdminLoginID: "admin@example.com", AdminName: "Admin"}, identitysdk.EmbeddedTransaction{Native: failed}); err == nil {
		_ = failed.Rollback()
		t.Fatal("historical default workspace was provisioned")
	}
	_ = failed.Rollback()
	weak, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "workspace-weak", AdminLoginID: "admin@example.com", AdminName: "Admin", InitialPassword: "weak"}, identitysdk.EmbeddedTransaction{Native: weak}); err == nil {
		_ = weak.Rollback()
		t.Fatal("weak host-supplied bootstrap password was accepted")
	}
	_ = weak.Rollback()

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bootstrap.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "workspace-primary", AdminLoginID: "admin@example.com", AdminName: "Admin", InitialPassword: "BootstrapAdmin1!"}, identitysdk.EmbeddedTransaction{Native: tx})
	if err != nil || result.InitialPassword != "BootstrapAdmin1!" {
		_ = tx.Rollback()
		t.Fatalf("bootstrap result=%#v error=%v", result, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertIdentityRowCount(t, db, "_identity_users", "workspace-primary", 1)
	assertIdentityRowCount(t, db, "_identity_user_role_assignments", "workspace-primary", 1)
	assertIdentityRowCount(t, db, "_identity_credentials", "workspace-primary", 1)
	assertIdentityRowCount(t, db, "_identity_permissions", "workspace-primary", standaloneIdentityPermissionCount())
}

func TestNormalBindingPreservesHostProvisionedImplicitAdminLogin(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "identity-bootstrap.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	registrar := &testEmbeddedMigrationRegistrar{}
	factory := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath})
	bootstrap, err := factory.OpenBootstrapWithDatabase(t.Context(), "runtime", identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: registrar})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	const password = "BootstrapAdmin1!"
	result, err := bootstrap.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{
		WorkspaceID: "workspace-primary", AdminLoginID: "management@example.test", AdminName: "Tenant Admin", InitialPassword: password,
	}, identitysdk.EmbeddedTransaction{Native: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}
	binding, err := factory.OpenWithDatabase(t.Context(), application, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: registrar})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	if _, err := binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	session, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: result.AdminLoginID, Password: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.WorkspaceID != string(application.WorkspaceID) || session.User.ID != "admin" || session.User.Email != result.AdminLoginID || !session.MustChangePassword {
		t.Fatalf("unexpected host-provisioned admin session: %#v", session)
	}
}

func TestEmbeddedWorkspaceProvisioningJoinsHostTransaction(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "embedded-provisioning.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}
	binding, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(t.Context(), application, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: &testEmbeddedMigrationRegistrar{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	publisher := binding.(identitysdk.ProjectRoleCatalogPublisher)
	if _, err := publisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{Application: application, Roles: []identitysdk.ProjectRoleDefinition{
		{Key: "admin", Name: "Administrator"},
		{Key: "workspace_viewer", Name: "Workspace viewer", ProvisionToWorkspaces: true},
		{Key: "headquarters_only", Name: "Headquarters only"},
	}}); err != nil {
		t.Fatal(err)
	}
	provisioner, ok := binding.(identitysdk.EmbeddedWorkspaceProvisioner)
	if !ok {
		t.Fatal("embedded Identity binding does not expose workspace provisioning")
	}

	rolledBack, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "workspace-rollback", AdminLoginID: "rollback@example.com", AdminName: "Rollback Admin"}, identitysdk.EmbeddedTransaction{Native: rolledBack}); err != nil {
		t.Fatal(err)
	}
	if err := rolledBack.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertIdentityRowCount(t, db, "_identity_users", "workspace-rollback", 0)
	assertIdentityRowCount(t, db, "_identity_permissions", "workspace-rollback", 0)

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provisioner.ProvisionWorkspaceIdentity(t.Context(), identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "workspace-active", AdminLoginID: "ADMIN@EXAMPLE.COM", AdminName: "Tenant Admin"}, identitysdk.EmbeddedTransaction{Native: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if result.AdminLoginID != "admin@example.com" || result.InitialPassword == "" || !result.MustChangePassword || result.ProvisionedRoles != 2 {
		_ = tx.Rollback()
		t.Fatalf("unexpected provisioning result: %#v", result)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertIdentityRowCount(t, db, "_identity_users", "workspace-active", 1)
	assertIdentityRowCount(t, db, "_identity_roles", "workspace-active", 2)
	assertIdentityRowCount(t, db, "_identity_user_role_assignments", "workspace-active", 1)
	assertIdentityRowCount(t, db, "_identity_credentials", "workspace-active", 1)
	assertIdentityRowCount(t, db, "_identity_permissions", "workspace-active", standaloneIdentityPermissionCount())
}

func TestEmbeddedWorkspaceProvisioningRollsBackEveryIdentityBoundary(t *testing.T) {
	points := []string{
		identitysdk.WorkspaceProvisionFailureAfterIdentityUser,
		identitysdk.WorkspaceProvisionFailureAfterIdentityRole,
		identitysdk.WorkspaceProvisionFailureAfterRoleAssignment,
		identitysdk.WorkspaceProvisionFailureAfterCredential,
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "embedded-provisioning.db")
			db, err := sql.Open("sqlite", databasePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}
			binding, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(t.Context(), application, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: &testEmbeddedMigrationRegistrar{}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = binding.Close(t.Context()) })
			provisioner := binding.(identitysdk.EmbeddedWorkspaceProvisioner)
			request := identitysdk.WorkspaceIdentityProvisionRequest{WorkspaceID: "workspace-rollback", AdminLoginID: "rollback@example.com", AdminName: "Rollback Admin"}

			failedTx, err := db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := provisioner.ProvisionWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{
				Native: failedTx, WorkspaceProvisionFailures: exactWorkspaceProvisionFailureInjector{target: point},
			})
			if !errors.Is(err, errInjectedWorkspaceProvisionFailure) || result != (identitysdk.WorkspaceIdentityProvisionResult{}) {
				_ = failedTx.Rollback()
				t.Fatalf("result=%#v error=%v", result, err)
			}
			if err := failedTx.Rollback(); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"_identity_users", "_identity_roles", "_identity_user_role_assignments", "_identity_credentials", "_identity_permissions"} {
				assertIdentityRowCount(t, db, table, request.WorkspaceID, 0)
			}

			retryTx, err := db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			retried, err := provisioner.ProvisionWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Native: retryTx})
			if err != nil || retried.InitialPassword == "" {
				_ = retryTx.Rollback()
				t.Fatalf("clean retry result=%#v error=%v", retried, err)
			}
			if err := retryTx.Commit(); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"_identity_users", "_identity_roles", "_identity_user_role_assignments", "_identity_credentials"} {
				assertIdentityRowCount(t, db, table, request.WorkspaceID, 1)
			}
			assertIdentityRowCount(t, db, "_identity_permissions", request.WorkspaceID, standaloneIdentityPermissionCount())
		})
	}
}

func assertIdentityRowCount(t *testing.T, db *sql.DB, table, workspaceID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "`+table+`" WHERE "workspace_id" = ?`, workspaceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s workspace %s count=%d want=%d", table, workspaceID, count, want)
	}
}

func standaloneIdentityPermissionCount() int {
	count := 0
	for _, action := range identityapplication.StandaloneIdentityAuthorizationSliceActions() {
		if action.Permission != nil {
			count++
		}
	}
	return count
}

func assertAllIdentityRows(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "`+table+`"`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s count=%d want=%d", table, count, want)
	}
}
