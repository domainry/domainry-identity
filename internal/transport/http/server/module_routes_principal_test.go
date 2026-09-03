package httpserver

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityModulePrincipalProjectsOnlyCurrentActionPermission(t *testing.T) {
	source := identitymodel.Principal{
		Known: true, WorkspaceID: "workspace", UserID: "auditor", AuthorizationRevision: "revision-1",
		Role: identitymodel.RoleSchema{Key: "auditor", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "audit.governance.read", "audit.governance.export", "malformed")},
	}
	principal := identityModuleSDKPrincipal(source, "audit.governance.read")
	if !principal.HasPermission("audit.governance.read") {
		t.Fatalf("module Action permission was not projected: %#v", principal.AccessBundle)
	}
	if len(principal.Permissions) != 1 || principal.Permissions[0] != "audit.governance.read" {
		t.Fatalf("module principal leaked role permissions: %#v", principal.Permissions)
	}
	if principal.HasPermission("audit.governance.export") || principal.HasPermission("malformed") {
		t.Fatalf("module principal received permissions outside the current Action: %#v", principal)
	}
	if len(principal.AccessBundle.FunctionGrants) != 1 || principal.AccessBundle.FunctionGrants[0].Resource != "audit.governance" || principal.AccessBundle.FunctionGrants[0].Action != "read" || principal.WorkspaceID != "workspace" || principal.UserID != "auditor" {
		t.Fatalf("module principal escaped its Identity authority: %#v", principal)
	}
}

func TestIdentityModulePrincipalDoesNotExpandAnotherExactPermission(t *testing.T) {
	principal := identityModuleSDKPrincipal(identitymodel.Principal{
		Known: true, WorkspaceID: "workspace", UserID: "admin", Role: identitymodel.RoleSchema{Key: "admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")},
	}, "audit.governance.read")
	if principal.HasPermission("audit.governance.read") || principal.HasPermission("audit.governance.export") || principal.HasPermission("audit.business.read") {
		t.Fatalf("another exact Permission expanded into module Action authority=%#v", principal.AccessBundle)
	}
	if len(principal.Permissions) != 0 || len(principal.AccessBundle.FunctionGrants) != 0 {
		t.Fatalf("unauthorized module principal received functional authority=%#v", principal)
	}
}
