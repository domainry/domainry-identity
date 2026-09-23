package module_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	principalresolver "github.com/domainry/domainry-identity-sdk/authorization/principal"
	identitymodule "github.com/domainry/domainry-identity/module"
)

func bindSharedSubjectLifecycle(t *testing.T, binding identitysdk.Binding) {
	t.Helper()
	binder, ok := binding.(identitysdk.SubjectLifecyclePersistenceBinding)
	if !ok {
		t.Fatal("module shared subject lifecycle persistence binder missing")
	}
	if err := binder.BindSubjectLifecyclePersistence(); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectErasureThroughModuleRevokesSessionsAndPreservesReceipt(t *testing.T) {
	catalog := identitysdk.ProjectRoleCatalog{
		InitialWorkspaceAdministratorRoleKey: "member",
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "member", Name: "Member", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "identity.users.list", DataScope: "owner"}}},
			{Key: "member_onboarding", Name: "Onboarding", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "identity.roles.list", DataScope: "all"}}},
		},
	}
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, catalog)
	request := workspaceIdentityBootstrapRequest("workspace-primary", "subject-erasure")
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
	credential, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: request.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := testIdentityFactory(identitymodule.Options{DatabaseDriver: "sqlite"}).OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(request.WorkspaceID), ApplicationKey: "runtime"}, identitysdk.DatabaseHandle{
		Pool: db, Driver: "sqlite", Migrations: &testEmbeddedMigrationRegistrar{}, WorkspaceResolver: testWorkspaceResolver{"workspace-primary": "workspace-primary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(context.Background()) })
	catalog.Application = identitysdk.ApplicationRef{ApplicationKey: "runtime"}
	if err := binding.(identitysdk.BootstrapProjectRoleCatalogBinder).BindBootstrapProjectRoleCatalog(t.Context(), catalog); err != nil {
		t.Fatal(err)
	}

	ctx := requestcontext.WithWorkspaceID(t.Context(), request.WorkspaceID)
	session, err := binding.Authentication().LoginWithPassword(ctx, identitysdk.PasswordLoginRequest{WorkspaceID: identitysdk.WorkspaceID(request.WorkspaceID), Login: credential.LoginID, Password: credential.InitialPassword})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := principalresolver.NewResolver(binding, principalresolver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Authenticate(ctx, session.AccessToken); err != nil {
		t.Fatal(err)
	}
	subjects, ok := binding.(identitysdk.SystemSubjectBinding)
	if !ok || subjects.SystemSubjects() == nil {
		t.Fatal("module subject port missing")
	}
	erase := identitysdk.SubjectErasureRequest{WorkspaceID: request.WorkspaceID, SubjectID: request.InitialAdminUserID, RequestID: "erase-1"}
	if _, err = subjects.SystemSubjects().PreviewSubject(ctx, erase.WorkspaceID, erase.SubjectID); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("unbound shared Lifecycle persistence error=%v", err)
	}
	bindSharedSubjectLifecycle(t, binding)
	if _, err = db.ExecContext(ctx, `INSERT INTO _subject_requests(id,workspace_id,request_type,kind,status,subject_id,resolved_identity,updated_at,payload_json) VALUES(?,?,'subject_request','erase','executing',?,?,?,'{}')`, erase.RequestID, erase.WorkspaceID, erase.SubjectID, erase.SubjectID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO _subject_steps(workspace_id,request_id,owner,operation,payload_json,completed_at) VALUES(?,?,'lifecycle','erase_fence','{}',?)`, erase.WorkspaceID, erase.RequestID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	wrong := erase
	wrong.WorkspaceID = "other-workspace"
	if _, err = subjects.SystemSubjects().EraseSubjectForRequest(ctx, wrong); err == nil {
		t.Fatal("cross workspace erasure accepted")
	}
	held := erase
	held.LegalHolds = json.RawMessage(`[{}]`)
	if _, err = subjects.SystemSubjects().EraseSubjectForRequest(ctx, held); err == nil {
		t.Fatal("held erasure accepted")
	}
	first, err := subjects.SystemSubjects().EraseSubjectForRequest(ctx, erase)
	if err != nil {
		t.Fatal(err)
	}
	again, err := subjects.SystemSubjects().EraseSubjectForRequest(ctx, erase)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("unstable receipt: %s %s %v", first, again, err)
	}
	if _, err = binding.Authentication().LoginWithPassword(ctx, identitysdk.PasswordLoginRequest{WorkspaceID: identitysdk.WorkspaceID(request.WorkspaceID), Login: credential.LoginID, Password: credential.InitialPassword}); err == nil {
		t.Fatal("erased user logged in")
	}
	if _, err = binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID)}); err == nil {
		t.Fatal("erased principal recovered")
	}
	if _, err = resolver.Authenticate(ctx, session.AccessToken); err == nil {
		t.Fatal("cached erased bearer authenticated")
	}
	// A fresh resolver must reject a previously valid signed bearer token.
	fresh, err := principalresolver.NewResolver(binding, principalresolver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.Authenticate(ctx, session.AccessToken); err == nil {
		t.Fatal("erased bearer authenticated")
	}
	exported, err := subjects.SystemSubjects().ExportSubject(ctx, erase.WorkspaceID, erase.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), credential.LoginID) || !strings.Contains(string(exported), `"status":"erased"`) {
		t.Fatalf("identity data survived: %s", exported)
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM _subject_steps WHERE workspace_id=? AND request_id=? AND owner='identity' AND operation='erase'`, erase.WorkspaceID, erase.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("shared execution step count %d: %v", count, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_subject_erasure_receipts'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy Identity erasure receipt table count %d: %v", count, err)
	}
	var version int64
	if err = db.QueryRowContext(ctx, `SELECT version FROM _identity_users WHERE workspace_id=? AND id=?`, erase.WorkspaceID, erase.SubjectID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	next := erase
	next.RequestID = "erase-2"
	if _, err = subjects.SystemSubjects().EraseSubjectForRequest(ctx, next); err == nil {
		t.Fatal("second erasure request bypassed the shared Lifecycle fence")
	}
	var nextVersion int64
	if err = db.QueryRowContext(ctx, `SELECT version FROM _identity_users WHERE workspace_id=? AND id=?`, erase.WorkspaceID, erase.SubjectID).Scan(&nextVersion); err != nil || nextVersion != version {
		t.Fatalf("tombstone changed on retry: %d %d %v", version, nextVersion, err)
	}
}
