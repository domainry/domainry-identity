package contract

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuthoringContractsPublishDutySpecificPermissions(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		actual     string
	}{
		{"account", "identity.users.write", IdentityUserAuthoringCapability().Execution.PermissionModel},
		{"department", "identity.departments.write", IdentityDepartmentAuthoringCapability().Execution.PermissionModel},
		{"role assignment", "identity.roles.write", IdentityUserRoleAssignmentAuthoringCapability().Execution.PermissionModel},
		{"role", "identity.roles.write", IdentityRoleAuthoringCapability().Execution.PermissionModel},
		{"permission", "identity.permissions.write", IdentityRolePermissionAuthoringCapability().Execution.PermissionModel},
		{"data scope", "identity.data_scopes.write", IdentityRoleDataScopeAuthoringCapability().Execution.PermissionModel},
		{"field policy", "identity.field_permissions.write", IdentityRoleFieldPermissionAuthoringCapability().Execution.PermissionModel},
		{"menu", "identity.menus.write", IdentityMenuAuthoringCapability().Execution.PermissionModel},
		{"role menu", "identity.menus.write", IdentityRoleMenuAssignmentAuthoringCapability().Execution.PermissionModel},
		{"business profile", "identity.profile_binding.manage", IdentityProfileBindingAuthoringCapability().Execution.PermissionModel},
		{"workforce profile", "identity.workforce.write", IdentityWorkforceProfileAuthoringCapability().Execution.PermissionModel},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.actual != test.permission {
				t.Fatalf("permission model=%q want=%q", test.actual, test.permission)
			}
		})
	}
}

func TestIdentityManagementDutiesDoNotGrantEachOther(t *testing.T) {
	tests := []struct {
		name    string
		granted string
		denied  []string
	}{
		{"workforce administrator", "identity.workforce.write", []string{"identity.profile_binding.manage", "identity.roles.write", "identity.security.write"}},
		{"member operations", "identity.profile_binding.manage", []string{"identity.users.read", "identity.users.write", "identity.workforce.write", "identity.roles.write", "identity.security.write"}},
		{"authorization administrator", "identity.roles.write", []string{"identity.workforce.write", "identity.profile_binding.manage", "identity.security.write"}},
		{"security administrator", "identity.security.write", []string{"identity.workforce.write", "identity.profile_binding.manage", "identity.roles.write"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			role := identitymodel.RoleSchema{Permissions: []string{test.granted}}
			if !IdentityRoleHasPermissionKey(role, test.granted) {
				t.Fatalf("own duty %q denied", test.granted)
			}
			for _, permission := range test.denied {
				if IdentityRoleHasPermissionKey(role, permission) {
					t.Fatalf("duty %q unexpectedly granted %q", test.granted, permission)
				}
			}
		})
	}
}
