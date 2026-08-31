package httpserver

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuditPrincipalProjectsExactAuditPermissions(t *testing.T) {
	principal := identityAuditSDKPrincipal(identitymodel.Principal{
		Known: true, WorkspaceID: "workspace", UserID: "auditor", AuthorizationRevision: "revision-1",
		Role: identitymodel.RoleSchema{Key: "auditor", Permissions: []string{"audit.governance.read", "audit.governance.export", "malformed"}},
	})
	if !principal.HasPermission("audit.governance.read") || !principal.HasPermission("audit.governance.export") {
		t.Fatalf("Audit permissions were not projected: %#v", principal.AccessBundle)
	}
	if principal.HasPermission("audit.business.read") || principal.WorkspaceID != "workspace" || principal.UserID != "auditor" {
		t.Fatalf("Audit principal escaped its Identity authority: %#v", principal)
	}
}

func TestIdentityAuditPrincipalPreservesWorkspaceAdminInheritance(t *testing.T) {
	principal := identityAuditSDKPrincipal(identitymodel.Principal{
		Known: true, WorkspaceID: "workspace", UserID: "admin", Role: identitymodel.RoleSchema{Key: "admin", Permissions: []string{"workspace.admin"}},
	})
	if !principal.HasPermission("audit.governance.read") || !principal.HasPermission("audit.governance.export") || principal.HasPermission("audit.business.read") {
		t.Fatalf("workspace administrator Audit authority=%#v", principal.AccessBundle)
	}
}
