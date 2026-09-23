package module_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	principalresolver "github.com/domainry/domainry-identity-sdk/authorization/principal"
	identitymodule "github.com/domainry/domainry-identity/module"
	"github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

func TestPrincipalRecoveryMatchesBearerAndRestrictsExplicitRole(t *testing.T) {
	catalog := identitysdk.ProjectRoleCatalog{
		InitialWorkspaceAdministratorRoleKey: "member",
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "member", Name: "Member", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "identity.users.list", DataScope: "owner"}}},
			{Key: "member_onboarding", Name: "Onboarding", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "identity.roles.list", DataScope: "all"}}},
		},
	}
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, catalog)
	request := workspaceIdentityBootstrapRequest("workspace-primary", "principal-recovery")
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
	roles, err := binding.Projection().ListRoles(ctx, identitysdk.ProjectionQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var onboardingID string
	for _, role := range roles {
		if role.Key == "member_onboarding" {
			onboardingID = role.ID
		}
	}
	if onboardingID == "" {
		t.Fatal("missing onboarding role")
	}
	renderer, err := dialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(renderer, "_identity_user_role_assignments", request.WorkspaceID).
		Columns("id", "user_id", "role_id", "source", "status", "created_at", "updated_at").Values("onboarding-assignment", request.InitialAdminUserID, onboardingID, "manual", "active", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, statement, arguments...); err != nil {
		t.Fatal(err)
	}
	session, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{WorkspaceID: identitysdk.WorkspaceID(request.WorkspaceID), Login: credential.LoginID, Password: credential.InitialPassword})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := principalresolver.NewResolver(binding, principalresolver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	httpPrincipal, err := authenticator.Authenticate(t.Context(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if session.WorkspaceID != request.WorkspaceID || httpPrincipal.AccessBundle.Subject.WorkspaceID != identitysdk.WorkspaceID(request.WorkspaceID) {
		t.Fatal("session and policy must use the resolved workspace")
	}
	if len(httpPrincipal.Roles) != 2 || !httpPrincipal.HasPermission("identity.users.list") || !httpPrincipal.HasPermission("identity.roles.list") {
		t.Fatal("fixture lacks effective multi-role authority")
	}
	for _, selected := range []string{"", httpPrincipal.RoleKey} {
		recovered, err := binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID), SessionRoleKey: selected})
		if err != nil {
			t.Fatal(err)
		}
		if recovered.Principal.RoleKey != httpPrincipal.RoleKey || recovered.Principal.AuthorizationRevision != httpPrincipal.AuthorizationRevision || string(recovered.AccessBundle.AuthorizationRevision) != httpPrincipal.AuthorizationRevision {
			t.Fatalf("session recovery differs: role=%q revision=%q", recovered.Principal.RoleKey, recovered.Principal.AuthorizationRevision)
		}
		actual, expected := recovered.AccessBundle, *httpPrincipal.AccessBundle
		actual.ExpiresAt = expected.ExpiresAt
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("HTTP and recovered policy/organization facts differ: recovered=%#v HTTP=%#v", actual, expected)
		}
	}
	narrow, err := binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID), RoleKey: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if !narrow.Principal.HasPermission("identity.users.list") || narrow.Principal.HasPermission("identity.roles.list") || narrow.Principal.AuthorizationRevision == httpPrincipal.AuthorizationRevision || narrow.Principal.AuthorizationRevision != string(narrow.AccessBundle.AuthorizationRevision) {
		t.Fatal("explicit role leaked effective union permissions or inconsistent revision")
	}
	if _, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID)}); err == nil {
		t.Fatal("missing workspace context was accepted")
	}
	if _, err := binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID), RoleKey: "member", SessionRoleKey: "member"}); err == nil {
		t.Fatal("ambiguous role selection accepted")
	}
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(renderer, "_identity_user_role_assignments", request.WorkspaceID).Set("status", "revoked").Where(query.Equal("id", "onboarding-assignment")).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, statement, arguments...); err != nil {
		t.Fatal(err)
	}
	changed, err := binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID), SessionRoleKey: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Principal.AuthorizationRevision == httpPrincipal.AuthorizationRevision || changed.Principal.HasPermission("identity.roles.list") {
		t.Fatal("revocation did not invalidate authorization")
	}
	if _, err := binding.Principals().Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: identitysdk.SubjectID(request.InitialAdminUserID), SessionRoleKey: "member_onboarding"}); err == nil || !strings.Contains(err.Error(), "session_role_unavailable") {
		t.Fatalf("revoked session role error=%v", err)
	}
}
