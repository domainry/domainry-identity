package service

import (
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityCanonicalRolePermissionsKeepsDistinctPoliciesForSamePermission(t *testing.T) {
	owner := identitysdk.ProjectDataPolicy{Operator: identitysdk.ProjectDataPolicyEq, FieldKey: "owner_id", SubjectClaim: identitysdk.ProjectSubjectClaimID}
	organization := identitysdk.ProjectDataPolicy{Operator: identitysdk.ProjectDataPolicyIn, FieldKey: "organization_id", SubjectClaim: identitysdk.ProjectSubjectClaimOrgScopeIDs}
	permissions := identityCanonicalRolePermissions([]identitymodel.RolePermission{
		{PermissionKey: "order.read", DataPolicy: &owner},
		{PermissionKey: "order.read", DataPolicy: &organization, AuditDenial: true},
		{PermissionKey: "order.read", DataPolicy: &owner, AuditDenial: true},
	})
	if len(permissions) != 2 {
		t.Fatalf("distinct relational policies were merged or duplicated: %#v", permissions)
	}
	for _, permission := range permissions {
		if permission.DataPolicy == nil || !permission.AuditDenial {
			t.Fatalf("canonical permission lost policy or merged audit flag: %#v", permission)
		}
	}
}
