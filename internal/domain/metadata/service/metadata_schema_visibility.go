package service

import (
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

// SnapshotForPrincipal projects only the schema facts a principal may use.
// Identity owns this authorization decision; reports, workflows, integrations
// and agents are intentionally outside this service.
func SnapshotForPrincipal(snapshot metadatamodel.MetadataSchemaSnapshot, principal identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	if !principal.Known {
		snapshot.Objects = nil
		snapshot.Views = nil
		snapshot.Actions = nil
		snapshot.GuardedWrites = nil
		snapshot.Roles = nil
		snapshot.PermissionSets = nil
		snapshot.PermissionSetGroups = nil
		snapshot.Guardrails = nil
		snapshot.IdentityProfileExtensions = nil
		return withSnapshotHash(snapshot)
	}
	if identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return withSnapshotHash(snapshot)
	}

	visibleObjectKeys := map[string]bool{}
	visibleObjects := make([]definitionmodel.ObjectSchema, 0, len(snapshot.Objects))
	for _, object := range snapshot.Objects {
		if !roleCanUseObject(principal.Role, object.Key) {
			continue
		}
		object.Fields = visibleFields(principal.Role, object)
		visibleObjects = append(visibleObjects, object)
		visibleObjectKeys[object.Key] = true
	}
	visibleViews := make([]definitionmodel.ViewSchema, 0, len(snapshot.Views))
	for _, view := range snapshot.Views {
		if visibleObjectKeys[view.ObjectKey] {
			visibleViews = append(visibleViews, view)
		}
	}
	visibleActions := make([]definitionmodel.ActionSchema, 0, len(snapshot.Actions))
	visibleActionKeys := map[string]bool{}
	for _, action := range snapshot.Actions {
		permission := strings.TrimSpace(action.RequiresPermission)
		if permission == "" {
			permission = strings.TrimSpace(action.Key)
		}
		if visibleObjectKeys[action.ObjectKey] && identitycontract.IdentityRoleHasPermissionKey(principal.Role, permission) {
			visibleActions = append(visibleActions, action)
			visibleActionKeys[action.Key] = true
		}
	}
	visibleWrites := make([]metadatamodel.MetadataGuardedWriteContract, 0, len(snapshot.GuardedWrites))
	for _, contract := range snapshot.GuardedWrites {
		if visibleObjectKeys[contract.ObjectKey] && visibleActionKeys[contract.ActionKey] {
			visibleWrites = append(visibleWrites, contract)
		}
	}
	visibleExtensions := make([]identitymodel.IdentityProfileExtension, 0, len(snapshot.IdentityProfileExtensions))
	for _, extension := range snapshot.IdentityProfileExtensions {
		if visibleObjectKeys[extension.ObjectKey] {
			visibleExtensions = append(visibleExtensions, extension)
		}
	}
	snapshot.Objects = visibleObjects
	snapshot.Views = visibleViews
	snapshot.Actions = visibleActions
	snapshot.GuardedWrites = visibleWrites
	snapshot.IdentityProfileExtensions = visibleExtensions
	snapshot.Roles = []identitymodel.RoleSchema{principal.Role}
	snapshot.PermissionSets = nil
	snapshot.PermissionSetGroups = nil
	snapshot.Guardrails = nil
	return withSnapshotHash(snapshot)
}

func roleCanUseObject(role identitymodel.RoleSchema, objectKey string) bool {
	for _, action := range []string{"read", "create", "update", "delete", "import", "export"} {
		if identitycontract.IdentityRoleAllows(role, objectKey, action) && identitycontract.IdentityRoleAllowsData(role, objectKey, action) {
			return true
		}
	}
	return false
}

func visibleFields(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema) []definitionmodel.FieldSchema {
	hasExplicit := false
	allowed := map[string]bool{}
	for _, permission := range role.FieldPermissions {
		if strings.TrimSpace(permission.ObjectKey) != strings.TrimSpace(object.Key) {
			continue
		}
		hasExplicit = true
		if permission.Read || permission.Write {
			allowed[strings.TrimSpace(permission.FieldKey)] = true
		}
	}
	if !hasExplicit {
		return append([]definitionmodel.FieldSchema(nil), object.Fields...)
	}
	fields := make([]definitionmodel.FieldSchema, 0, len(object.Fields))
	for _, field := range object.Fields {
		if allowed[field.Key] && !identitycontract.IdentityRoleGuardrailDeniesField(role, object.Key, field.Key, "read") {
			fields = append(fields, field)
		}
	}
	return fields
}

func withSnapshotHash(snapshot metadatamodel.MetadataSchemaSnapshot) metadatamodel.MetadataSchemaSnapshot {
	snapshot.SchemaHash = SchemaSnapshotHash(snapshot)
	snapshot.SnapshotVersion = snapshot.SchemaHash
	return snapshot
}
