package identity

import (
	"slices"
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

func TestIdentityAuthoringProjectionResolvesEveryOperationFromCanonicalActions(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range projection.Domain().Capabilities {
		if capability.Execution == nil || capability.Execution.PermissionModel != authoringcontract.CapabilityPermissionModelExactAction {
			t.Fatalf("capability %q permission model=%v", capability.Key, capability.Execution)
		}
		if len(capability.ConfigurationRoutes) == 0 || len(capability.Permissions) == 0 {
			t.Fatalf("capability %q routes=%v permissions=%v", capability.Key, capability.ConfigurationRoutes, capability.Permissions)
		}
		for _, route := range capability.ConfigurationRoutes {
			action, found := projection.ActionForRoute(route)
			if !found {
				t.Fatalf("capability %q route %q has no Action", capability.Key, route)
			}
			switch action.Authorization.Strategy {
			case actioncontract.AuthorizationExactRolePermission, actioncontract.AuthorizationSelfOrPermission:
				if action.Permission == nil || action.Permission.Key != action.Key || !slices.Contains(capability.Permissions, action.Key) {
					t.Fatalf("capability %q route %q action=%+v permissions=%v", capability.Key, route, action, capability.Permissions)
				}
			default:
				if action.Permission != nil || slices.Contains(capability.Permissions, action.Key) {
					t.Fatalf("capability %q non-role Action %q leaked into permissions", capability.Key, action.Key)
				}
			}
		}
	}
}

func TestIdentityAuthoringProjectionKeepsCRUDAndMetadataOperationsIndependent(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]authoringcontract.CapabilityAuthoringDefinition{}
	for _, capability := range projection.Domain().Capabilities {
		byKey[capability.Key] = capability
	}
	for capabilityKey, expected := range map[string][]string{
		"identity.user": {
			"identity.users.create", "identity.users.delete", "identity.users.disable", "identity.users.enable",
			"identity.users.get", "identity.users.update", "identity.users.validate", "identity.users.versions",
		},
		"identity.role": {
			metadatacontract.MetadataActionDefinitionDisable, metadatacontract.MetadataActionDefinitionGet,
			metadatacontract.MetadataActionDefinitionRollback, metadatacontract.MetadataActionDefinitionUpsert,
			metadatacontract.MetadataActionDefinitionValidate, metadatacontract.MetadataActionDefinitionVersions,
		},
		"identity.workforce_profile": {
			"identity.workforce.create", "identity.workforce.get", "identity.workforce.update", "identity.workforce.validate",
		},
	} {
		actual := byKey[capabilityKey].Permissions
		if !slices.Equal(actual, expected) {
			t.Fatalf("capability %q permissions=%v want=%v", capabilityKey, actual, expected)
		}
	}
	userGet, found := projection.ActionForRoute("GET /identity/users/{userID}")
	if !found || userGet.Key != "identity.users.get" || userGet.Authorization.Strategy != actioncontract.AuthorizationSelfOrPermission {
		t.Fatalf("user get Action=%+v found=%v", userGet, found)
	}
}

func TestIdentityAuthoringProjectionRejectsRouteOutsideCanonicalMatrix(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	domain := identitycontract.IdentityAuthoringDomain()
	domain.Capabilities[0].ConfigurationRoutes = append(domain.Capabilities[0].ConfigurationRoutes, "POST /identity/unregistered")
	if _, err := registry.ProjectAuthoringDomain(domain); err == nil {
		t.Fatal("authoring route outside the Action registry was accepted")
	}
}
