package module_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodule "github.com/domainry/domainry-identity/module"
	_ "modernc.org/sqlite"
)

func TestEmbeddedWorkspaceProvisioningJoinsHostTransaction(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "embedded-provisioning.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	application := identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "runtime"}
	binding, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(t.Context(), application, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath})
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
	assertIdentityRowCount(t, db, "domainry_identity__identity_users", "workspace-rollback", 0)

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
	assertIdentityRowCount(t, db, "domainry_identity__identity_users", "workspace-active", 1)
	assertIdentityRowCount(t, db, "domainry_identity__identity_roles", "workspace-active", 2)
	assertIdentityRowCount(t, db, "domainry_identity__identity_user_role_assignments", "workspace-active", 1)
	assertIdentityRowCount(t, db, "domainry_identity__identity_credentials", "workspace-active", 1)
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
