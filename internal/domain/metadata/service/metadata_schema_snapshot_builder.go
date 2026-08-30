package service

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	"sort"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

type SchemaSnapshotState struct {
	TemplateID, TemplateVersion, Name string
	Objects                           []definitionmodel.ObjectSchema
	Actions                           []definitionmodel.ActionSchema
	Roles                             []identitymodel.RoleSchema
	PermissionSets                    []identitymodel.IdentityPermissionSet
	PermissionSetGroups               []identitymodel.IdentityPermissionSetGroup
	Guardrails                        []identitymodel.IdentityGuardrailPolicy
	IdentityProfileExtensions         []identitymodel.IdentityProfileExtension
}

func BuildSchemaSnapshot(state SchemaSnapshotState) metadatamodel.MetadataSchemaSnapshot {
	objects := append([]definitionmodel.ObjectSchema(nil), state.Objects...)
	actions := append([]definitionmodel.ActionSchema(nil), state.Actions...)
	roles := append([]identitymodel.RoleSchema(nil), state.Roles...)
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	sort.Slice(actions, func(i, j int) bool { return actions[i].Key < actions[j].Key })
	sort.Slice(roles, func(i, j int) bool { return roles[i].Key < roles[j].Key })
	snapshot := metadatamodel.MetadataSchemaSnapshot{
		TemplateID: state.TemplateID, TemplateVersion: state.TemplateVersion, Name: state.Name,
		Objects: objects, Actions: actions,
		GuardedWrites: GuardedWriteContracts(actions), Roles: roles,
		PermissionSets:            append([]identitymodel.IdentityPermissionSet(nil), state.PermissionSets...),
		PermissionSetGroups:       append([]identitymodel.IdentityPermissionSetGroup(nil), state.PermissionSetGroups...),
		Guardrails:                append([]identitymodel.IdentityGuardrailPolicy(nil), state.Guardrails...),
		IdentityProfileExtensions: append([]identitymodel.IdentityProfileExtension(nil), state.IdentityProfileExtensions...),
	}
	snapshot.SchemaHash = SchemaSnapshotHash(snapshot)
	snapshot.SnapshotVersion = snapshot.SchemaHash
	return snapshot
}
