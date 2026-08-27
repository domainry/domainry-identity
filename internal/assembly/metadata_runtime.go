package assembly

import (
	"context"
	"sync"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

// MetadataRuntime is an in-process, read-optimized projection of the persisted
// metadata catalog. It is deliberately not the Plane Runtime engine.
type MetadataRuntime struct {
	mu       sync.RWMutex
	snapshot metadatamodel.MetadataSchemaSnapshot
}

func NewMetadataRuntime(state metadataservice.SchemaSnapshotState) *MetadataRuntime {
	return &MetadataRuntime{snapshot: metadataservice.BuildSchemaSnapshot(state)}
}

func (r *MetadataRuntime) ApplyManifestMetadata(templateID, templateVersion, name string, objects []definitionmodel.ObjectSchema, views []definitionmodel.ViewSchema, actions []definitionmodel.ActionSchema, roles []identitymodel.RoleSchema, permissionSets []identitymodel.IdentityPermissionSet, permissionSetGroups []identitymodel.IdentityPermissionSetGroup, guardrails []identitymodel.IdentityGuardrailPolicy, profileExtensions []identitymodel.IdentityProfileExtension) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot = metadataservice.BuildSchemaSnapshot(metadataservice.SchemaSnapshotState{
		TemplateID: templateID, TemplateVersion: templateVersion, Name: name,
		Objects: objects, Views: views, Actions: actions, Roles: roles,
		PermissionSets: permissionSets, PermissionSetGroups: permissionSetGroups,
		Guardrails: guardrails, IdentityProfileExtensions: profileExtensions,
	})
}

func (r *MetadataRuntime) Schema() metadatamodel.MetadataSchemaSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

func (r *MetadataRuntime) SchemaForPrincipal(_ context.Context, principal identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	return metadataservice.SnapshotForPrincipal(r.Schema(), principal)
}

func snapshotState(snapshot metadatamodel.MetadataSchemaSnapshot) metadataservice.SchemaSnapshotState {
	return metadataservice.SchemaSnapshotState{
		TemplateID: snapshot.TemplateID, TemplateVersion: snapshot.TemplateVersion, Name: snapshot.Name,
		Objects: snapshot.Objects, Views: snapshot.Views, Actions: snapshot.Actions, Roles: snapshot.Roles,
		PermissionSets: snapshot.PermissionSets, PermissionSetGroups: snapshot.PermissionSetGroups,
		Guardrails: snapshot.Guardrails, IdentityProfileExtensions: snapshot.IdentityProfileExtensions,
	}
}
