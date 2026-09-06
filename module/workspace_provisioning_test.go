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
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	workspaceRequest := workspaceIdentityBootstrapV2Request("workspace-primary", "workspace-bootstrap")
	workspaceTx := beginBootstrapTx(t, db)
	workspaceReceipt, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), workspaceRequest, identitysdk.EmbeddedTransaction{Executor: workspaceTx})
	if err != nil {
		_ = workspaceTx.Rollback()
		t.Fatal(err)
	}
	if err := workspaceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrapV2(t, bootstrap, workspaceReceipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
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
	if receipt.Replayed || receipt.RoleKey != identitysdk.WorkspaceBootstrapRoleTenantAdmin || receipt.UserID == "" || receipt.ReceiptID == "" {
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
	if roleKey != identitysdk.WorkspaceBootstrapRoleTenantAdmin || orgID != workspaceRequest.CompanyID {
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

func TestWorkspaceIdentityBootstrapV2CreatesFixedGraphAndReleasesCredentialAfterCommit(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	if _, legacy := bootstrap.(identitysdk.EmbeddedWorkspaceProvisioner); legacy {
		t.Fatal("Protocol V3 bootstrap binding exposes V1 legacy provisioning")
	}
	request := workspaceIdentityBootstrapV2Request("workspace-primary", "invocation-primary")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if receipt.Replayed || receipt.ReceiptID == "" || receipt.ContractVersion != identitysdk.CurrentWorkspaceIdentityBootstrapContractVersion || receipt.ContractHash != identitysdk.CurrentWorkspaceIdentityBootstrapContractHash {
		_ = tx.Rollback()
		t.Fatalf("receipt=%#v", receipt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("credential was released before the host reported transaction completion")
	}
	completeWorkspaceIdentityBootstrapV2(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)

	assertIdentityRowCount(t, db, "_identity_organization_units", request.WorkspaceID, 2)
	assertIdentityRowCount(t, db, "_identity_users", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_roles", request.WorkspaceID, 4)
	assertIdentityRowCount(t, db, "_identity_user_role_assignments", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_credentials", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_workspace_bootstrap_receipts", request.WorkspaceID, 1)
	assertIdentityRowCount(t, db, "_identity_permissions", request.WorkspaceID, standaloneIdentityPermissionCount())

	assertBootstrapOrganizationGraph(t, db, request)
	assertBootstrapRolesAndAssignment(t, db, request)
	credential, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil || credential.LoginID != "admin@example.test" || credential.InitialPassword == "" || !credential.MustChangePassword {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("one-time bootstrap credential was replayed")
	}
	assertBootstrapPasswordNotPersisted(t, db, credential.InitialPassword)
}

func TestWorkspaceIdentityBootstrapV2ReplayAndDuplicateAreDeterministic(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	request := workspaceIdentityBootstrapV2Request("workspace-replay", "invocation-replay")
	firstTx := beginBootstrapTx(t, db)
	first, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: firstTx})
	if err != nil {
		_ = firstTx.Rollback()
		t.Fatal(err)
	}
	if err := firstTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrapV2(t, bootstrap, first, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)

	replayTx := beginBootstrapTx(t, db)
	replay, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: replayTx})
	if err != nil || !replay.Replayed || replay.ReceiptID != first.ReceiptID {
		_ = replayTx.Rollback()
		t.Fatalf("replay=%#v error=%v", replay, err)
	}
	if err := replayTx.Commit(); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{
		"_identity_organization_units": 2, "_identity_users": 1, "_identity_roles": 4,
		"_identity_user_role_assignments": 1, "_identity_credentials": 1,
		"_identity_workspace_bootstrap_receipts": 1,
	} {
		assertIdentityRowCount(t, db, table, request.WorkspaceID, want)
	}

	conflict := request
	conflict.FirstStoreName = "Changed Store"
	conflictTx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), conflict, identitysdk.EmbeddedTransaction{Executor: conflictTx}); err == nil {
		_ = conflictTx.Rollback()
		t.Fatal("same invocation with a different graph was accepted")
	}
	_ = conflictTx.Rollback()

	duplicate := request
	duplicate.InvocationID = "another-invocation"
	duplicateTx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), duplicate, identitysdk.EmbeddedTransaction{Executor: duplicateTx}); err == nil {
		_ = duplicateTx.Rollback()
		t.Fatal("second bootstrap invocation for one Workspace was accepted")
	}
	_ = duplicateTx.Rollback()
}

func TestWorkspaceIdentityBootstrapV2RollbackCompletionDestroysVolatileCredential(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	request := workspaceIdentityBootstrapV2Request("workspace-host-rollback", "host-rollback")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrapV2(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionRolledBack)
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID}); err == nil {
		t.Fatal("rolled-back bootstrap credential remained claimable")
	}
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

	retryTx := beginBootstrapTx(t, db)
	retry, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: retryTx})
	if err != nil {
		_ = retryTx.Rollback()
		t.Fatal(err)
	}
	if err := retryTx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrapV2(t, bootstrap, retry, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: retry.ReceiptID}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceIdentityBootstrapV2FailsClosedForMissingRoleAndPreexistingCrossWorkspaceParent(t *testing.T) {
	missingRoles := workspaceBootstrapRoleDefinitions()[:3]
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, missingRoles)
	request := workspaceIdentityBootstrapV2Request("workspace-missing-role", "missing-role")
	tx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx}); err == nil {
		_ = tx.Rollback()
		t.Fatal("bootstrap without the complete four-role catalog succeeded")
	}
	_ = tx.Rollback()
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

	complete, completeDB := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	cross := workspaceIdentityBootstrapV2Request("workspace-cross-parent", "cross-parent")
	if _, err := completeDB.ExecContext(t.Context(), `INSERT INTO _identity_organization_units (id, workspace_id, code, name, node_type, parent_id, path, ancestor_ids, depth, sort_order, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"orphan-store", cross.WorkspaceID, "ORPHAN", "Orphan", "store", "company-from-another-workspace", "/company-from-another-workspace/orphan-store", `["company-from-another-workspace"]`, 1, 0, "active", "now", "now"); err != nil {
		t.Fatal(err)
	}
	crossTx := beginBootstrapTx(t, completeDB)
	if _, err := complete.BootstrapWorkspaceIdentityV2(t.Context(), cross, identitysdk.EmbeddedTransaction{Executor: crossTx}); err == nil {
		_ = crossTx.Rollback()
		t.Fatal("bootstrap adopted a preexisting cross-Workspace parent graph")
	}
	_ = crossTx.Rollback()
	assertIdentityRowCount(t, completeDB, "_identity_organization_units", cross.WorkspaceID, 1)
	for _, table := range []string{"_identity_users", "_identity_roles", "_identity_user_role_assignments", "_identity_credentials", "_identity_workspace_bootstrap_receipts"} {
		assertIdentityRowCount(t, completeDB, table, cross.WorkspaceID, 0)
	}
}

func TestWorkspaceIdentityBootstrapV2RejectsUnpinnedContract(t *testing.T) {
	bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
	request := workspaceIdentityBootstrapV2Request("workspace-contract", "contract")
	request.ContractHash = strings.Repeat("0", 64)
	tx := beginBootstrapTx(t, db)
	if _, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: tx}); err == nil {
		_ = tx.Rollback()
		t.Fatal("unpinned Workspace bootstrap contract was accepted")
	}
	_ = tx.Rollback()
	assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)
}

func TestWorkspaceIdentityBootstrapV2RollsBackEveryBoundaryAndRetriesCleanly(t *testing.T) {
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
			bootstrap, db := openWorkspaceIdentityBootstrapV2(t, workspaceBootstrapRoleDefinitions())
			request := workspaceIdentityBootstrapV2Request("workspace-rollback", "rollback-"+point)
			failedTx := beginBootstrapTx(t, db)
			result, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{
				Executor: failedTx, WorkspaceProvisionFailures: exactWorkspaceProvisionFailureInjector{target: point},
			})
			if !errors.Is(err, errInjectedWorkspaceProvisionFailure) || result != (identitysdk.WorkspaceIdentityBootstrapV2Receipt{}) {
				_ = failedTx.Rollback()
				t.Fatalf("result=%#v error=%v", result, err)
			}
			if err := failedTx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertWorkspaceBootstrapZero(t, db, request.WorkspaceID)

			retryTx := beginBootstrapTx(t, db)
			retried, err := bootstrap.BootstrapWorkspaceIdentityV2(t.Context(), request, identitysdk.EmbeddedTransaction{Executor: retryTx})
			if err != nil || retried.Replayed || retried.ReceiptID == "" {
				_ = retryTx.Rollback()
				t.Fatalf("retry=%#v error=%v", retried, err)
			}
			if err := retryTx.Commit(); err != nil {
				t.Fatal(err)
			}
			completeWorkspaceIdentityBootstrapV2(t, bootstrap, retried, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
			if _, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredentialV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: retried.ReceiptID}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func openWorkspaceIdentityBootstrapV2(t *testing.T, roles []identitysdk.ProjectRoleDefinition) (identitysdk.BootstrapBinding, *sql.DB) {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "identity-bootstrap-v2.db")
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
	if err := bootstrap.BindBootstrapProjectRoleCatalog(t.Context(), identitysdk.ProjectRoleCatalog{
		Application: identitysdk.ApplicationRef{ApplicationKey: "runtime"}, Roles: roles,
	}); err != nil {
		t.Fatal(err)
	}
	return bootstrap, db
}

func workspaceBootstrapRoleDefinitions() []identitysdk.ProjectRoleDefinition {
	return []identitysdk.ProjectRoleDefinition{
		{Key: identitysdk.WorkspaceBootstrapRoleTenantAdmin, Name: "Platform administrator"},
		{Key: identitysdk.WorkspaceBootstrapRoleHeadquartersAdmin, Name: "Headquarters admin"},
		{Key: identitysdk.WorkspaceBootstrapRoleStoreManager, Name: "Store manager"},
		{Key: identitysdk.WorkspaceBootstrapRoleStaff, Name: "Staff"},
	}
}

func completeWorkspaceIdentityBootstrapV2(t *testing.T, bootstrap identitysdk.BootstrapBinding, receipt identitysdk.WorkspaceIdentityBootstrapV2Receipt, outcome identitysdk.WorkspaceIdentityBootstrapTransactionOutcome) {
	t.Helper()
	if err := bootstrap.CompleteWorkspaceIdentityBootstrapV2(t.Context(), identitysdk.WorkspaceIdentityBootstrapCompletion{
		WorkspaceID: receipt.WorkspaceID, ReceiptID: receipt.ReceiptID, Outcome: outcome,
	}); err != nil {
		t.Fatal(err)
	}
}

func workspaceIdentityBootstrapV2Request(workspaceID, invocationID string) identitysdk.WorkspaceIdentityBootstrapV2Request {
	return identitysdk.WorkspaceIdentityBootstrapV2Request{
		ContractVersion: identitysdk.CurrentWorkspaceIdentityBootstrapContractVersion,
		ContractHash:    identitysdk.CurrentWorkspaceIdentityBootstrapContractHash,
		InvocationID:    invocationID, WorkspaceID: workspaceID,
		CompanyID: workspaceID + "-company", CompanyCode: "COMPANY", CompanyName: "Example Company",
		FirstStoreID: workspaceID + "-store", FirstStoreCode: "STORE-001", FirstStoreName: "First Store",
		InitialAdminUserID: workspaceID + "-admin", InitialAdminLoginID: "ADMIN@EXAMPLE.TEST", InitialAdminName: "Initial Admin",
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

func assertBootstrapOrganizationGraph(t *testing.T, db *sql.DB, request identitysdk.WorkspaceIdentityBootstrapV2Request) {
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

func assertBootstrapRolesAndAssignment(t *testing.T, db *sql.DB, request identitysdk.WorkspaceIdentityBootstrapV2Request) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT role_key FROM _identity_roles WHERE workspace_id = ? ORDER BY role_key`, request.WorkspaceID)
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
	if strings.Join(keys, ",") != "headquarters_admin,staff,store_manager,tenant_admin" {
		t.Fatalf("role keys=%v", keys)
	}
	var platformLabel string
	if err := db.QueryRowContext(t.Context(), `SELECT label FROM _identity_roles WHERE workspace_id = ? AND role_key = ?`, request.WorkspaceID, identitysdk.WorkspaceBootstrapRoleTenantAdmin).Scan(&platformLabel); err != nil {
		t.Fatal(err)
	}
	if platformLabel != "Platform administrator" {
		t.Fatalf("tenant_admin display label=%q", platformLabel)
	}
	var roleKey, source string
	if err := db.QueryRowContext(t.Context(), `SELECT r.role_key, a.source FROM _identity_user_role_assignments a JOIN _identity_roles r ON r.workspace_id = a.workspace_id AND r.id = a.role_id WHERE a.workspace_id = ? AND a.user_id = ?`, request.WorkspaceID, request.InitialAdminUserID).Scan(&roleKey, &source); err != nil {
		t.Fatal(err)
	}
	if roleKey != identitysdk.WorkspaceBootstrapRoleHeadquartersAdmin || source != "workspace_bootstrap_v2" {
		t.Fatalf("assigned role=%q source=%q", roleKey, source)
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
		"_identity_credentials", "_identity_permissions", "_identity_workspace_bootstrap_receipts",
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
