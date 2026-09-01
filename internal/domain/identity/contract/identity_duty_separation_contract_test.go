package contract

import (
	"testing"

	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuthoringContractsDeclareRegistryResolvedPermissionModel(t *testing.T) {
	for _, capability := range IdentityAuthoringDomain().Capabilities {
		if capability.Execution == nil || capability.Execution.PermissionModel != authoringcontract.CapabilityPermissionModelExactAction {
			t.Fatalf("capability %q permission model=%v", capability.Key, capability.Execution)
		}
		if len(capability.Permissions) != 0 {
			t.Fatalf("capability %q hard-codes permissions %v before Action projection", capability.Key, capability.Permissions)
		}
	}
}

func TestIdentityManagementDutiesDoNotGrantEachOther(t *testing.T) {
	tests := []struct {
		name    string
		granted string
		denied  []string
	}{
		{"workforce administrator", "identity.workforce.update", []string{"identity.profile_bindings.command", "identity.role_permissions.publish", "identity.users.force_logout"}},
		{"member operations", "identity.profile_bindings.command", []string{"identity.users.get", "identity.users.update", "identity.workforce.update", "identity.role_permissions.publish", "identity.users.force_logout"}},
		{"authorization administrator", "identity.role_permissions.publish", []string{"identity.workforce.update", "identity.profile_bindings.command", "identity.users.force_logout"}},
		{"security administrator", "identity.users.force_logout", []string{"identity.workforce.update", "identity.profile_bindings.command", "identity.role_permissions.publish"}},
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
