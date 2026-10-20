package composition

import (
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

func TestMetadataRuntimeComposesProjectObjectsWithoutReplacingIdentityObjects(t *testing.T) {
	runtime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{Objects: []definitionmodel.ObjectSchema{{Key: "identity_user", Fields: []definitionmodel.FieldSchema{{Key: "email"}}}}})
	runtime.ReplaceProjectObjects([]definitionmodel.ObjectSchema{
		{Key: "customer", Fields: []definitionmodel.FieldSchema{{Key: "name"}}},
		{Key: "identity_user", Fields: []definitionmodel.FieldSchema{{Key: "application_override"}}},
	})
	objects := runtime.EffectiveAccessObjects()
	if len(objects) != 2 || objects[0].Key != "customer" || objects[1].Key != "identity_user" {
		t.Fatalf("objects=%#v", objects)
	}
	if len(objects[1].Fields) != 1 || objects[1].Fields[0].Key != "email" {
		t.Fatalf("Identity-owned object was replaced: %#v", objects[1])
	}
	if schema := runtime.Schema(); len(schema.Objects) != 1 || schema.Objects[0].Key != "identity_user" {
		t.Fatalf("project catalog polluted Identity metadata: %#v", schema.Objects)
	}

	runtime.ReplaceProjectObjects(nil)
	objects = runtime.EffectiveAccessObjects()
	if len(objects) != 1 || objects[0].Key != "identity_user" {
		t.Fatalf("project catalog was not replaceable: %#v", objects)
	}
}

func TestMetadataRuntimeReappliesProjectRolesAfterSourceReload(t *testing.T) {
	runtime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{
		Roles: []identitymodel.RoleSchema{
			{Key: "admin", Name: "Identity admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.users.list")},
			{Key: "reviewer", Name: "Reviewer"},
		},
	})
	runtime.ReplaceProjectRoles([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Runtime admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "scheduler.definitions.list")},
		{Key: "operator", Name: "Runtime operator"},
	})

	roles := runtime.EffectiveRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Reloaded Identity admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")},
		{Key: "reviewer", Name: "Reloaded reviewer"},
		{Key: "auditor", Name: "New authored role"},
	})
	if len(roles) != 4 || roles[0].Key != "admin" || roles[1].Key != "auditor" || roles[2].Key != "operator" || roles[3].Key != "reviewer" {
		t.Fatalf("roles=%#v", roles)
	}
	if roles[0].Name != "Runtime admin" || len(roles[0].Permissions) != 1 || roles[0].Permissions[0].PermissionKey != "scheduler.definitions.list" {
		t.Fatalf("project admin overlay was lost: %#v", roles[0])
	}
	if roles[3].Name != "Reloaded reviewer" {
		t.Fatalf("source role update was lost: %#v", roles[3])
	}

	runtime.ReplaceProjectRoles(nil)
	roles = runtime.EffectiveRoleDefinitions(runtime.Schema().Roles)
	if len(roles) != 2 || roles[0].Name != "Identity admin" || roles[1].Key != "reviewer" {
		t.Fatalf("project roles were not replaceable: %#v", roles)
	}
}

func TestMetadataRuntimeAppliesOnlyFieldPermissionOverrideToProjectRole(t *testing.T) {
	runtime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{})
	runtime.ReplaceProjectRoles([]identitymodel.RoleSchema{{
		Key: "analyst", Name: "Project analyst",
		Permissions:      identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "customer.read"),
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "email", Read: false}},
	}})

	roles := runtime.EffectiveRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "analyst", Name: "Persisted field overlay",
		FieldPermissions:               []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "email", Read: true}},
		ProjectFieldPermissionOverride: true,
	}})
	if len(roles) != 1 || roles[0].Name != "Project analyst" || len(roles[0].Permissions) != 1 || roles[0].Permissions[0].PermissionKey != "customer.read" {
		t.Fatalf("project role authority changed: %#v", roles)
	}
	if len(roles[0].FieldPermissions) != 1 || !roles[0].FieldPermissions[0].Read {
		t.Fatalf("field permission override not applied: %#v", roles[0].FieldPermissions)
	}
}

func TestMetadataRuntimeComposesFunctionalAndFieldOverlaysWithoutReplacingRoleGovernance(t *testing.T) {
	runtime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{})
	runtime.ReplaceProjectRoles([]identitymodel.RoleSchema{{Key: "sales", Name: "销售", Audience: identitymodel.IdentityRoleAudienceUser, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskElevated, GrantableRoleKeys: []string{"analyst"}, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "customer.read"), FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "email", Read: false}}}})
	overlay := identitymodel.RoleSchema{Key: "sales", Name: "Untrusted replacement", RiskLevel: identitymodel.IdentityRoleRiskNormal, GrantableRoleKeys: []string{"*"}, ProjectPermissionOverride: true, ProjectFieldPermissionOverride: true, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "customer.read", "customer.update"), FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "email", Read: true}}}
	roles := runtime.EffectiveRoleDefinitions([]identitymodel.RoleSchema{overlay})
	if len(roles) != 1 || roles[0].Name != "销售" || roles[0].RiskLevel != identitymodel.IdentityRoleRiskElevated || len(roles[0].GrantableRoleKeys) != 1 || roles[0].GrantableRoleKeys[0] != "analyst" || len(roles[0].Permissions) != 2 || !roles[0].FieldPermissions[0].Read {
		t.Fatalf("ownership lost: %+v", roles)
	}
	overlay.ProjectPermissionOverride = false
	roles = runtime.EffectiveRoleDefinitions([]identitymodel.RoleSchema{overlay})
	if len(roles[0].Permissions) != 1 {
		t.Fatal("unmarked functional overlay was applied")
	}
}
