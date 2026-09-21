package module_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodule "github.com/domainry/domainry-identity/module"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func TestInstallationAdministratorBootstrapIsEmbeddedAtomicAuditedAndFirstOnly(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, installationBootstrapRoleCatalog())
	workspaceRequest := workspaceIdentityBootstrapRequest("workspace-primary", "workspace-bootstrap")
	workspaceTx := beginBootstrapTx(t, db)
	workspaceReceipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), workspaceRequest, identitysdk.EmbeddedTransaction{Executor: workspaceTx})
	if err != nil {
		_ = workspaceTx.Rollback()
		t.Fatal(err)
	}
	if err := workspaceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, workspaceReceipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	if err := bootstrap.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	binding, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite"}).OpenWithDatabase(
		t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"},
		identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", Migrations: &testEmbeddedMigrationRegistrar{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(context.Background()) })
	provider, ok := binding.(identitysdk.EmbeddedInstallationAdministratorBootstrapBinding)
	if !ok || provider.InstallationAdministratorBootstrap() == nil {
		t.Fatalf("ordinary embedded binding does not expose startup capability: %T", binding)
	}
	capability := provider.InstallationAdministratorBootstrap()
	request := identitymodulehost.InstallationAdministratorBootstrapRequest{
		ContractVersion: identitymodulehost.CurrentInstallationAdministratorBootstrapContractVersion,
		ContractHash:    identitymodulehost.CurrentInstallationAdministratorBootstrapContractHash,
		InvocationID:    "installation-admin-first", WorkspaceID: "workspace-primary",
		LoginID: "installation-admin@example.test", Name: "Installation Administrator",
	}
	rolledBackTx := beginBootstrapTx(t, db)
	rolledBackReceipt, err := capability.BootstrapInstallationAdministratorV1(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: rolledBackTx})
	if err != nil {
		_ = rolledBackTx.Rollback()
		t.Fatal(err)
	}
	if err := rolledBackTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := capability.CompleteInstallationAdministratorBootstrapV1(t.Context(), identitymodulehost.InstallationAdministratorBootstrapCompletion{
		WorkspaceID: request.WorkspaceID, ReceiptID: rolledBackReceipt.ReceiptID, Outcome: identitysdk.WorkspaceIdentityBootstrapTransactionRolledBack,
	}); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		query string
		args  []any
	}{
		{query: `SELECT COUNT(*) FROM _identity_users WHERE workspace_id=? AND email=?`, args: []any{request.WorkspaceID, request.LoginID}},
		{query: `SELECT COUNT(*) FROM _identity_installation_administrator_bootstrap_receipts WHERE workspace_id=?`, args: []any{request.WorkspaceID}},
		{query: `SELECT COUNT(*) FROM _audit_events WHERE workspace_id=? AND event=?`, args: []any{request.WorkspaceID, "identity.installation_administrator.bootstrap"}},
	} {
		var count int
		if err := db.QueryRowContext(t.Context(), check.query, check.args...).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rolled-back installation administrator state count=%d error=%v", count, err)
		}
	}
	tx := beginBootstrapTx(t, db)
	receipt, err := capability.BootstrapInstallationAdministratorV1(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if receipt.Replayed || receipt.RoleKey != identitymodulehost.InstallationAdministratorRoleKey || receipt.UserID == "" || receipt.ReceiptID == "" {
		_ = tx.Rollback()
		t.Fatalf("receipt=%#v", receipt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := capability.CompleteInstallationAdministratorBootstrapV1(t.Context(), identitymodulehost.InstallationAdministratorBootstrapCompletion{
		WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID, Outcome: identitysdk.WorkspaceIdentityBootstrapTransactionCommitted,
	}); err != nil {
		t.Fatal(err)
	}
	credential, err := capability.ClaimInstallationAdministratorCredentialV1(t.Context(), identitymodulehost.InstallationAdministratorCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil || credential.LoginID != request.LoginID || credential.InitialPassword == "" || !credential.MustChangePassword {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if err := capability.AcknowledgeInstallationAdministratorCredentialDeliveryV1(t.Context(), identitymodulehost.InstallationAdministratorCredentialDeliveryAcknowledgment{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err != nil {
		t.Fatal(err)
	}
	var roleKey, orgID string
	if err := db.QueryRowContext(t.Context(), `SELECT role.role_key, user.org_id FROM _identity_users user JOIN _identity_user_role_assignments assignment ON assignment.workspace_id=user.workspace_id AND assignment.user_id=user.id JOIN _identity_roles role ON role.workspace_id=assignment.workspace_id AND role.id=assignment.role_id WHERE user.workspace_id=? AND user.id=?`, request.WorkspaceID, receipt.UserID).Scan(&roleKey, &orgID); err != nil {
		t.Fatal(err)
	}
	if roleKey != identitymodulehost.InstallationAdministratorRoleKey || orgID != workspaceRequest.CompanyID {
		t.Fatalf("role=%q org=%q", roleKey, orgID)
	}
	var audits int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id=? AND event=? AND record_id=?`, request.WorkspaceID, "identity.installation_administrator.bootstrap", receipt.UserID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d error=%v", audits, err)
	}
	replayTx := beginBootstrapTx(t, db)
	replay, err := capability.BootstrapInstallationAdministratorV1(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: replayTx})
	if err != nil || !replay.Replayed || !replay.CredentialClaimed || !replay.CredentialDelivered {
		_ = replayTx.Rollback()
		t.Fatalf("replay=%#v error=%v", replay, err)
	}
	_ = replayTx.Rollback()
	second := request
	second.InvocationID, second.LoginID = "installation-admin-second", "second-admin@example.test"
	secondTx := beginBootstrapTx(t, db)
	if _, err := capability.BootstrapInstallationAdministratorV1(t.Context(), second, identitysdk.EmbeddedTransaction{Executor: secondTx}); err == nil {
		_ = secondTx.Rollback()
		t.Fatal("second installation administrator issuance was accepted")
	}
	_ = secondTx.Rollback()
}

var errInjectedWorkspaceProvisionFailure = errors.New("injected workspace provisioning failure")

type exactWorkspaceProvisionFailureInjector struct{ target string }

func (injector exactWorkspaceProvisionFailureInjector) InjectWorkspaceProvisionFailure(point string) error {
	if point == injector.target {
		return errInjectedWorkspaceProvisionFailure
	}
	return nil
}

func TestWorkspaceIdentityBootstrapCreatesGraphAndReleasesCredentialAfterCommit(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	if _, exposed := bootstrap.(identitysdk.EmbeddedWorkspaceProvisioner); exposed {
		t.Fatal("bootstrap binding exposes the earlier role-selectable provisioner")
	}
	request := workspaceIdentityBootstrapRequest("workspace-primary", "invocation-primary")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if receipt.Replayed || receipt.ReceiptID == "" || receipt.ContractVersion != identitysdk.WorkspaceIdentityBootstrapContractVersion || receipt.ContractHash != identitysdk.WorkspaceIdentityBootstrapContractHash {
		_ = tx.Rollback()
		t.Fatalf("receipt=%#v", receipt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("credential was released before the host reported transaction completion")
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)

	assertIdentityRowCount(t, db, "_identity_organization_units", request.WorkspaceID, 2)
	assertIdentityRowCount(t, db, "_identity_users", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_roles", request.WorkspaceID, 3)
	assertIdentityRowCount(t, db, "_identity_user_role_assignments", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_credentials", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_workspace_bootstrap_receipts", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_permissions", request.WorkspaceID, standaloneIdentityPermissionCount())

	assertBootstrapOrganizationGraph(t, db, request)
	credential, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil || credential.LoginID != "admin@example.test" || credential.InitialPassword != request.InitialAdminPassword || !credential.MustChangePassword {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("one-time bootstrap credential was replayed")
	}
	assertBootstrapPasswordNotPersisted(t, db, credential.InitialPassword)
}

func TestWorkspaceIdentityBootstrapRequiresTheCompilerOwnedManifestPassword(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	request := workspaceIdentityBootstrapRequest("workspace-password", "invocation-password")
	request.InitialAdminPassword = ""
	tx := beginBootstrapTx(t, db)
	_, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	_ = tx.Rollback()
	var identityErr *identitysdk.Error
	if !errors.As(err, &identityErr) || identityErr.Params["field"] != "initial_admin_password" {
		t.Fatalf("missing manifest password error=%v", err)
	}
}

func TestWorkspaceIdentityBootstrapCopiesNavigationTemplatePerWorkspace(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	navigation := identitysdk.ProjectNavigationCatalog{
		ContractVersion: identitysdk.ProjectNavigationContractVersion,
		Menus: []identitysdk.ProjectMenuDefinition{
			{Key: "business.crm", Label: map[string]string{"en": "CRM"}, Route: "/crm", SortOrder: 10},
			{Key: "business.crm.leads", Label: map[string]string{"en": "Leads"}, Route: "/crm/leads", ParentKey: "business.crm", SortOrder: 20},
		},
		RoleMenuSets: []identitysdk.ProjectRoleMenuSet{{RoleKey: "sales_rep", MenuKeys: []string{"business.crm.leads"}}},
	}
	if err := bootstrap.BindBootstrapProjectNavigationCatalog(t.Context(), navigation); err != nil {
		t.Fatal(err)
	}
	materialize := func(workspaceID string) identitysdk.WorkspaceIdentityBootstrapReceipt {
		t.Helper()
		request := workspaceIdentityBootstrapRequest(workspaceID, "navigation-"+workspaceID)
		tx := beginBootstrapTx(t, db)
		receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if receipt.NavigationCatalogSHA256 == "" {
			_ = tx.Rollback()
			t.Fatal("workspace bootstrap receipt omitted the navigation template digest")
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
		return receipt
	}
	materialize("workspace-navigation-a")
	if _, err := db.ExecContext(t.Context(), `UPDATE _identity_menus SET label=? WHERE workspace_id=? AND menu_key=?`, "Tenant A CRM", "workspace-navigation-a", "business.crm"); err != nil {
		t.Fatal(err)
	}
	materialize("workspace-navigation-b")

	type workspaceNavigation struct {
		rootID, childID, parentID, rootLabel string
		assignments                          int
	}
	load := func(workspaceID string) workspaceNavigation {
		t.Helper()
		var item workspaceNavigation
		if err := db.QueryRowContext(t.Context(), `SELECT id,label FROM _identity_menus WHERE workspace_id=? AND menu_key=?`, workspaceID, "business.crm").Scan(&item.rootID, &item.rootLabel); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(t.Context(), `SELECT id,parent_id FROM _identity_menus WHERE workspace_id=? AND menu_key=?`, workspaceID, "business.crm.leads").Scan(&item.childID, &item.parentID); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_role_menu_assignments a JOIN _identity_roles r ON r.workspace_id=a.workspace_id AND r.id=a.role_id JOIN _identity_menus m ON m.workspace_id=a.workspace_id AND m.id=a.menu_id WHERE a.workspace_id=? AND r.role_key=? AND m.menu_key=?`, workspaceID, "sales_rep", "business.crm.leads").Scan(&item.assignments); err != nil {
			t.Fatal(err)
		}
		return item
	}
	first, second := load("workspace-navigation-a"), load("workspace-navigation-b")
	if first.rootID == second.rootID || first.childID == second.childID {
		t.Fatalf("workspace menu copies share IDs: first=%+v second=%+v", first, second)
	}
	if first.parentID != first.rootID || second.parentID != second.rootID || first.assignments != 1 || second.assignments != 1 {
		t.Fatalf("workspace navigation graph differs: first=%+v second=%+v", first, second)
	}
	if first.rootLabel != "Tenant A CRM" || second.rootLabel != "CRM" {
		t.Fatalf("tenant customization leaked or was overwritten: first=%q second=%q", first.rootLabel, second.rootLabel)
	}
}

func TestWorkspaceIdentityBootstrapMaterializesM1RolesAndAssignsExplicitAdministrator(t *testing.T) {
	catalog := m1WorkspaceBootstrapRoleCatalog()
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, catalog)
	request := workspaceIdentityBootstrapRequest("workspace-m1", "invocation-m1")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if receipt.RoleCatalogSHA256 == "" || receipt.InitialWorkspaceAdministratorRoleKey != "crm_acceptance_admin" {
		_ = tx.Rollback()
		t.Fatalf("receipt role policy=%#v", receipt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("M1 credential was released before commit completion")
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	credential, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil || credential.InitialPassword == "" {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	assertIdentityRowCount(t, db, "_identity_roles", request.WorkspaceID, 3)
	rows, err := db.QueryContext(t.Context(), `SELECT role_key FROM _identity_roles WHERE workspace_id=? ORDER BY role_key`, request.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	if got := strings.Join(keys, ","); got != "crm_acceptance_admin,sales_director,sales_rep" {
		t.Fatalf("M1 materialized roles=%q", got)
	}
	var assigned, persistedDigest, persistedAdministrator string
	if err := db.QueryRowContext(t.Context(), `SELECT role.role_key FROM _identity_user_role_assignments assignment JOIN _identity_roles role ON role.workspace_id=assignment.workspace_id AND role.id=assignment.role_id WHERE assignment.workspace_id=? AND assignment.user_id=?`, request.WorkspaceID, request.InitialAdminUserID).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT role_catalog_sha256, initial_workspace_administrator_role_key FROM _identity_workspace_bootstrap_receipts WHERE workspace_id=?`, request.WorkspaceID).Scan(&persistedDigest, &persistedAdministrator); err != nil {
		t.Fatal(err)
	}
	if assigned != "crm_acceptance_admin" || persistedDigest != receipt.RoleCatalogSHA256 || persistedAdministrator != "crm_acceptance_admin" {
		t.Fatalf("assigned=%q persisted digest=%q administrator=%q", assigned, persistedDigest, persistedAdministrator)
	}
}

func TestWorkspaceIdentityBootstrapMaterializesProvisionedBusinessProfileRoleWithoutAssigningIt(t *testing.T) {
	catalog := identitysdk.ProjectRoleCatalog{
		InitialWorkspaceAdministratorRoleKey: "admin",
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "admin", Name: "Admin", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true},
			{Key: "profile_member", Name: "Profile member", Audience: "business_profile", AssignmentMode: "request_only", RequiredBindingKey: "member", ProvisionToWorkspaces: true},
			{Key: "internal_service", Name: "Internal service", Audience: "service", AssignmentMode: "system_managed"},
		},
	}
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, catalog)
	request := workspaceIdentityBootstrapRequest("workspace-profile-role", "invocation-profile-role")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	assertIdentityRowCount(t, db, "_identity_roles", request.WorkspaceID, 2)
	var assigned string
	if err := db.QueryRowContext(t.Context(), `SELECT role.role_key FROM _identity_user_role_assignments assignment JOIN _identity_roles role ON role.workspace_id=assignment.workspace_id AND role.id=assignment.role_id WHERE assignment.workspace_id=?`, request.WorkspaceID).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if assigned != "admin" {
		t.Fatalf("business-profile request role was assigned to initial admin: %q", assigned)
	}
}

func TestWorkspaceIdentityBootstrapRolePolicyFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		catalog identitysdk.ProjectRoleCatalog
		code    string
	}{
		{name: "explicit administrator missing", catalog: identitysdk.ProjectRoleCatalog{InitialWorkspaceAdministratorRoleKey: "missing", Roles: m1WorkspaceBootstrapRoleCatalog().Roles}, code: "identity.workspace_bootstrap_initial_administrator_role_missing"},
		{name: "request-only administrator", catalog: identitysdk.ProjectRoleCatalog{InitialWorkspaceAdministratorRoleKey: "request_admin", Roles: []identitysdk.ProjectRoleDefinition{{Key: "request_admin", Name: "Request admin", Audience: "user", AssignmentMode: "request_only", ProvisionToWorkspaces: true}}}, code: "identity.workspace_bootstrap_initial_administrator_role_invalid"},
		{name: "business-profile administrator", catalog: identitysdk.ProjectRoleCatalog{InitialWorkspaceAdministratorRoleKey: "profile_admin", Roles: []identitysdk.ProjectRoleDefinition{{Key: "profile_admin", Name: "Profile admin", Audience: "business_profile", AssignmentMode: "manual", ProvisionToWorkspaces: true}}}, code: "identity.workspace_bootstrap_initial_administrator_role_invalid"},
		{name: "service role marked provisionable", catalog: identitysdk.ProjectRoleCatalog{InitialWorkspaceAdministratorRoleKey: "admin", Roles: []identitysdk.ProjectRoleDefinition{{Key: "admin", Name: "Admin", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true}, {Key: "service", Name: "Service", Audience: "service", AssignmentMode: "system_managed", ProvisionToWorkspaces: true}}}, code: "identity.workspace_bootstrap_role_catalog_invalid"},
		{name: "system-managed role marked provisionable", catalog: identitysdk.ProjectRoleCatalog{InitialWorkspaceAdministratorRoleKey: "admin", Roles: []identitysdk.ProjectRoleDefinition{{Key: "admin", Name: "Admin", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true}, {Key: "profile", Name: "Profile", Audience: "business_profile", AssignmentMode: "system_managed", ProvisionToWorkspaces: true}}}, code: "identity.workspace_bootstrap_role_catalog_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrap, _ := openWorkspaceIdentityBootstrapUnbound(t)
			test.catalog.Application = identitysdk.ApplicationRef{ApplicationKey: "runtime"}
			err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), test.catalog)
			var sdkErr *identitysdk.Error
			if !errors.As(err, &sdkErr) || sdkErr.Code != test.code {
				t.Fatalf("BindBootstrapProjectRoleCatalog() error=%v, want %s", err, test.code)
			}
		})
	}

	bootstrap, _ := openWorkspaceIdentityBootstrapUnbound(t)
	err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), identitysdk.ProjectRoleCatalog{
		Application: identitysdk.ApplicationRef{ApplicationKey: "runtime"},
		Roles:       m1WorkspaceBootstrapRoleCatalog().Roles,
	})
	var sdkErr *identitysdk.Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.workspace_bootstrap_initial_administrator_role_required" {
		t.Fatalf("missing explicit M1 administrator error=%v", err)
	}
}

func TestWorkspaceIdentityBootstrapDetectsRoleCatalogDriftOnReplay(t *testing.T) {
	catalog := m1WorkspaceBootstrapRoleCatalog()
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, catalog)
	request := workspaceIdentityBootstrapRequest("workspace-catalog-drift", "invocation-catalog-drift")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	catalog.Roles[2].Name = "Sales representative changed"
	catalog.Application = identitysdk.ApplicationRef{ApplicationKey: "runtime"}
	if err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), catalog); err != nil {
		t.Fatal(err)
	}
	replayTx := beginBootstrapTx(t, db)
	_, err = bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: replayTx})
	_ = replayTx.Rollback()
	var sdkErr *identitysdk.Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.workspace_bootstrap_idempotency_conflict" {
		t.Fatalf("catalog drift replay error=%v", err)
	}
}

func TestWorkspaceIdentityBootstrapReplayAndDuplicateAreDeterministic(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	request := workspaceIdentityBootstrapRequest("workspace-replay", "invocation-replay")
	firstTx := beginBootstrapTx(t, db)
	first, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: firstTx})
	if err != nil {
		_ = firstTx.Rollback()
		t.Fatal(err)
	}
	if err := firstTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, first, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)

	replayTx := beginBootstrapTx(t, db)
	replay, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: replayTx})
	if err != nil || !replay.Replayed || replay.ReceiptID != first.ReceiptID {
		_ = replayTx.Rollback()
		t.Fatalf("replay=%#v error=%v", replay, err)
	}
	if err := replayTx.Commit(); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{
		"_identity_organization_units": 2, "_identity_users": 1, "_identity_roles": 3,
		"_identity_user_role_assignments": 1, "_identity_credentials": 1,
		"_identity_workspace_bootstrap_receipts": 1,
	} {
		assertIdentityRowCount(t, db, table, request.WorkspaceID, want)
	}

	conflict := request
	conflict.FirstStoreName = "Changed Store"
	conflictTx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), conflict, identitysdk.EmbeddedTransaction{Executor: conflictTx}); err == nil {
		_ = conflictTx.Rollback()
		t.Fatal("same invocation with a different graph was accepted")
	}
	_ = conflictTx.Rollback()

	duplicate := request
	duplicate.InvocationID = "another-invocation"
	duplicateTx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), duplicate, identitysdk.EmbeddedTransaction{Executor: duplicateTx}); err == nil {
		_ = duplicateTx.Rollback()
		t.Fatal("second bootstrap invocation for one Workspace was accepted")
	}
	_ = duplicateTx.Rollback()
}

func TestWorkspaceIdentityBootstrapRollbackCompletionDestroysVolatileCredential(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	request := workspaceIdentityBootstrapRequest("workspace-host-rollback", "host-rollback")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionRolledBack)
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("rolled-back bootstrap credential remained claimable")
	}
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

	retryTx := beginBootstrapTx(t, db)
	retry, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: retryTx})
	if err != nil {
		_ = retryTx.Rollback()
		t.Fatal(err)
	}
	if err := retryTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, retry, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: retry.ReceiptID}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceIdentityBootstrapFailsClosedForMissingRoleAndPreexistingCrossWorkspaceParent(t *testing.T) {
	missingRoles := m1WorkspaceBootstrapRoleCatalog().Roles[:3]
	bootstrap, db := openWorkspaceIdentityBootstrapUnbound(t)
	if err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), identitysdk.ProjectRoleCatalog{Application: identitysdk.ApplicationRef{ApplicationKey: "runtime"}, Roles: missingRoles}); err == nil {
		t.Fatal("bootstrap binder accepted a catalog without an explicit administrator")
	}
	request := workspaceIdentityBootstrapRequest("workspace-missing-role", "missing-role")
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

	complete, completeDB := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	cross := workspaceIdentityBootstrapRequest("workspace-cross-parent", "cross-parent")
	if _, err := completeDB.ExecContext(t.Context(), `INSERT INTO _identity_organization_units (id, workspace_id, code, name, node_type, parent_id, path, ancestor_ids, depth, sort_order, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"orphan-store", cross.WorkspaceID, "ORPHAN", "Orphan", "store", "company-from-another-workspace", "/company-from-another-workspace/orphan-store", `["company-from-another-workspace"]`, 1, 0, "active", "now", "now"); err != nil {
		t.Fatal(err)
	}
	crossTx := beginBootstrapTx(t, completeDB)
	if _, err := complete.BootstrapWorkspaceIdentity(t.Context(), cross, identitysdk.EmbeddedTransaction{Executor: crossTx}); err == nil {
		_ = crossTx.Rollback()
		t.Fatal("bootstrap adopted a preexisting cross-Workspace parent graph")
	}
	_ = crossTx.Rollback()
	assertIdentityRowCount(t, completeDB, "_identity_organization_units", cross.WorkspaceID, 1)
	for _, table := range []string{"_identity_users", "_identity_roles", "_identity_user_role_assignments", "_identity_credentials", "_identity_workspace_bootstrap_receipts"} {
		assertIdentityRowCount(t, completeDB, table, cross.WorkspaceID, 0)
	}
}

func TestWorkspaceIdentityBootstrapRejectsUnpinnedContract(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
	request := workspaceIdentityBootstrapRequest("workspace-contract", "contract")
	request.ContractHash = strings.Repeat("0", 64)
	tx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx}); err == nil {
		_ = tx.Rollback()
		t.Fatal("unpinned Workspace bootstrap contract was accepted")
	}
	_ = tx.Rollback()
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)
}

func TestWorkspaceIdentityBootstrapRollsBackEveryBoundaryAndRetriesCleanly(t *testing.T) {
	points := []string{
		identitysdk.WorkspaceProvisionFailureAfterCompany,
		identitysdk.WorkspaceProvisionFailureAfterFirstStore,
		identitysdk.WorkspaceProvisionFailureAfterIdentityUser,
		identitysdk.WorkspaceProvisionFailureAfterIdentityRole,
		identitysdk.WorkspaceProvisionFailureAfterRoleAssignment,
		identitysdk.WorkspaceProvisionFailureAfterCredential,
		identitysdk.WorkspaceProvisionFailureAfterBootstrapReceipt,
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, m1WorkspaceBootstrapRoleCatalog())
			request := workspaceIdentityBootstrapRequest("workspace-rollback", "rollback-"+point)
			failedTx := beginBootstrapTx(t, db)
			result, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{
				Executor: failedTx, WorkspaceProvisionFailures: exactWorkspaceProvisionFailureInjector{target: point},
			})
			if !errors.Is(err, errInjectedWorkspaceProvisionFailure) || result != (identitysdk.WorkspaceIdentityBootstrapReceipt{}) {
				_ = failedTx.Rollback()
				t.Fatalf("result=%#v error=%v", result, err)
			}
			if err := failedTx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

			retryTx := beginBootstrapTx(t, db)
			retried, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: retryTx})
			if err != nil || retried.Replayed || retried.ReceiptID == "" {
				_ = retryTx.Rollback()
				t.Fatalf("retry=%#v error=%v", retried, err)
			}
			if err := retryTx.Commit(); err != nil {
				t.Fatal(err)
			}
			completeWorkspaceIdentityBootstrap(t, bootstrap, retried, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
			if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: retried.ReceiptID}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func openWorkspaceIdentityBootstrapCatalog(t *testing.T, catalog identitysdk.ProjectRoleCatalog) (identitysdk.BootstrapBinding, *sql.DB) {
	t.Helper()
	bootstrap, db := openWorkspaceIdentityBootstrapUnbound(t)
	catalog.Application = identitysdk.ApplicationRef{ApplicationKey: "runtime"}
	if err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), catalog); err != nil {
		t.Fatal(err)
	}
	return bootstrap, db
}

func openWorkspaceIdentityBootstrapUnbound(t *testing.T) (identitysdk.BootstrapBinding, *sql.DB) {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "identity-bootstrap.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bootstrap, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenBootstrapWithDatabase(
		t.Context(), "runtime", identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: &testEmbeddedMigrationRegistrar{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bootstrap.Close(t.Context()) })
	return bootstrap, db
}

func m1WorkspaceBootstrapRoleCatalog() identitysdk.ProjectRoleCatalog {
	return identitysdk.ProjectRoleCatalog{
		InitialWorkspaceAdministratorRoleKey: "crm_acceptance_admin",
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "crm_acceptance_admin", Name: "CRM acceptance administrator", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true},
			{Key: "sales_director", Name: "Sales director", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true},
			{Key: "sales_rep", Name: "Sales representative", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true},
			{Key: "crm_internal_service", Name: "CRM internal service", Audience: "service", AssignmentMode: "system_managed"},
			{Key: "crm_sync_service", Name: "CRM sync service", Audience: "service", AssignmentMode: "system_managed"},
		},
	}
}

func installationBootstrapRoleCatalog() identitysdk.ProjectRoleCatalog {
	return identitysdk.ProjectRoleCatalog{
		InitialWorkspaceAdministratorRoleKey: "workspace_admin",
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "workspace_admin", Name: "Workspace administrator", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true},
			{Key: identitymodulehost.InstallationAdministratorRoleKey, Name: "Installation administrator", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true},
		},
	}
}

func completeWorkspaceIdentityBootstrap(t *testing.T, bootstrap identitysdk.BootstrapBinding, receipt identitysdk.WorkspaceIdentityBootstrapReceipt, outcome identitysdk.WorkspaceIdentityBootstrapTransactionOutcome) {
	t.Helper()
	if err := bootstrap.CompleteWorkspaceIdentityBootstrap(t.Context(), identitysdk.WorkspaceIdentityBootstrapCompletion{
		WorkspaceID: receipt.WorkspaceID, ReceiptID: receipt.ReceiptID, Outcome: outcome,
	}); err != nil {
		t.Fatal(err)
	}
}

func workspaceIdentityBootstrapRequest(workspaceID, invocationID string) identitysdk.WorkspaceIdentityBootstrapRequest {
	login := "ADMIN@EXAMPLE.TEST"
	if workspaceID != "workspace-primary" {
		login = workspaceID + "-admin@example.test"
	}
	return identitysdk.WorkspaceIdentityBootstrapRequest{
		ContractVersion: identitysdk.WorkspaceIdentityBootstrapContractVersion,
		ContractHash:    identitysdk.WorkspaceIdentityBootstrapContractHash,
		InvocationID:    invocationID, WorkspaceID: workspaceID,
		CompanyID: workspaceID + "-company", CompanyCode: "COMPANY", CompanyName: "Example Company",
		FirstStoreID: workspaceID + "-store", FirstStoreCode: "STORE-001", FirstStoreName: "First Store",
		InitialAdminUserID: workspaceID + "-admin", InitialAdminLoginID: login, InitialAdminName: "Initial Admin",
		InitialAdminPassword: "domainry!123",
	}
}

func beginBootstrapTx(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func assertBootstrapOrganizationGraph(t *testing.T, db *sql.DB, request identitysdk.WorkspaceIdentityBootstrapRequest) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT id, node_type, COALESCE(parent_id, ''), path, ancestor_ids, depth, status FROM _identity_organization_units WHERE workspace_id = ? ORDER BY depth, id`, request.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type organization struct {
		id, nodeType, parentID, path, ancestors, status string
		depth                                           int
	}
	var items []organization
	for rows.Next() {
		var item organization
		if err := rows.Scan(&item.id, &item.nodeType, &item.parentID, &item.path, &item.ancestors, &item.depth, &item.status); err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	if len(items) != 2 || items[0] != (organization{id: request.CompanyID, nodeType: "company", path: "/" + request.CompanyID, ancestors: "[]", status: "active"}) || items[1] != (organization{id: request.FirstStoreID, nodeType: "store", parentID: request.CompanyID, path: "/" + request.CompanyID + "/" + request.FirstStoreID, ancestors: `["` + request.CompanyID + `"]`, depth: 1, status: "active"}) {
		t.Fatalf("organizations=%#v", items)
	}
	var orgID, accountType, status string
	if err := db.QueryRowContext(t.Context(), `SELECT org_id, account_type, status FROM _identity_users WHERE workspace_id = ? AND id = ?`, request.WorkspaceID, request.InitialAdminUserID).Scan(&orgID, &accountType, &status); err != nil {
		t.Fatal(err)
	}
	if orgID != request.CompanyID || accountType != "human" || status != "active" {
		t.Fatalf("initial admin org=%q type=%q status=%q", orgID, accountType, status)
	}
}

func assertBootstrapPasswordNotPersisted(t *testing.T, db *sql.DB, password string) {
	t.Helper()
	var fingerprint, version, hash, login string
	if err := db.QueryRowContext(t.Context(), `SELECT request_fingerprint, contract_version, contract_hash, initial_admin_login_id FROM _identity_workspace_bootstrap_receipts`).Scan(&fingerprint, &version, &hash, &login); err != nil {
		t.Fatal(err)
	}
	for _, persisted := range []string{fingerprint, version, hash, login} {
		if strings.Contains(persisted, password) {
			t.Fatal("bootstrap receipt persisted the initial password")
		}
	}
	var passwordHash string
	if err := db.QueryRowContext(t.Context(), `SELECT password_hash FROM _identity_credentials`).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if passwordHash == password || strings.Contains(passwordHash, password) {
		t.Fatal("credential row persisted the initial password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		t.Fatalf("returned one-time password does not match persisted hash: %v", err)
	}
}

func assertWorkspaceBootstrapZero(t *testing.T, db *sql.DB, workspaceID string) {
	t.Helper()
	for _, table := range []string{
		"_identity_organization_units", "_identity_users", "_identity_roles", "_identity_user_role_assignments",
		"_identity_credentials", "_identity_permissions", "_identity_workspace_bootstrap_receipts", "_identity_applications",
	} {
		assertIdentityRowCount(t, db, table, workspaceID, 0)
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
