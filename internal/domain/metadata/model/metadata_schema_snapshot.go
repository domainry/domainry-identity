package metadatamodel

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type MetadataSchemaSnapshot struct {
	TemplateID                string                                     `json:"template_id"`
	TemplateVersion           string                                     `json:"template_version"`
	Name                      string                                     `json:"name,omitempty"`
	SchemaHash                string                                     `json:"schema_hash"`
	SnapshotVersion           string                                     `json:"snapshot_version"`
	Objects                   []definitionmodel.ObjectSchema             `json:"objects"`
	Actions                   []definitionmodel.ActionSchema             `json:"actions"`
	GuardedWrites             []MetadataGuardedWriteContract             `json:"guarded_writes,omitempty"`
	Roles                     []identitymodel.RoleSchema                 `json:"roles"`
	PermissionSets            []identitymodel.IdentityPermissionSet      `json:"permission_sets,omitempty"`
	PermissionSetGroups       []identitymodel.IdentityPermissionSetGroup `json:"permission_set_groups,omitempty"`
	Guardrails                []identitymodel.IdentityGuardrailPolicy    `json:"guardrails,omitempty"`
	IdentityProfileExtensions []identitymodel.IdentityProfileExtension   `json:"identity_profile_extensions,omitempty"`
}

type MetadataGuardedWriteContract struct {
	ObjectKey       string   `json:"object_key"`
	Operation       string   `json:"operation"`
	ActionKey       string   `json:"action_key"`
	ActionKind      string   `json:"action_kind"`
	Label           string   `json:"label,omitempty"`
	Endpoint        string   `json:"endpoint"`
	RequiresRecord  bool     `json:"requires_record,omitempty"`
	BlocksRawCRUD   bool     `json:"blocks_raw_crud"`
	IdempotencyKeys []string `json:"idempotency_keys,omitempty"`
}
