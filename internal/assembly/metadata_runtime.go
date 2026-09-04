package assembly

import (
	"context"
	"sort"
	"strings"
	"sync"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

// MetadataRuntime is an in-process, read-optimized projection of the persisted
// metadata catalog. It is deliberately not the Plane Runtime engine.
type MetadataRuntime struct {
	mu             sync.RWMutex
	snapshot       metadatamodel.MetadataSchemaSnapshot
	projectObjects []definitionmodel.ObjectSchema
}

func NewMetadataRuntime(state metadataservice.SchemaSnapshotState) *MetadataRuntime {
	return &MetadataRuntime{snapshot: metadataservice.BuildSchemaSnapshot(state)}
}

func (r *MetadataRuntime) ActivateMetadata(snapshot metadatamodel.MetadataSchemaSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot = metadataservice.BuildSchemaSnapshot(snapshotState(snapshot))
}

func (r *MetadataRuntime) Schema() metadatamodel.MetadataSchemaSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

// ReplaceProjectObjects refreshes the application-owned object directory used
// only by Identity's effective field-access projection. The Identity metadata
// snapshot remains source-owned and is never overwritten by an embedding host.
func (r *MetadataRuntime) ReplaceProjectObjects(objects []definitionmodel.ObjectSchema) {
	projectObjects := append([]definitionmodel.ObjectSchema(nil), objects...)
	sort.Slice(projectObjects, func(left, right int) bool { return projectObjects[left].Key < projectObjects[right].Key })
	r.mu.Lock()
	defer r.mu.Unlock()
	r.projectObjects = projectObjects
}

// EffectiveAccessObjects combines source-owned Identity objects with the
// embedding application's published objects. Identity-owned definitions win
// on a key collision, keeping module ownership fail-closed.
func (r *MetadataRuntime) EffectiveAccessObjects() []definitionmodel.ObjectSchema {
	r.mu.RLock()
	defer r.mu.RUnlock()
	objects := append([]definitionmodel.ObjectSchema(nil), r.snapshot.Objects...)
	seen := make(map[string]bool, len(objects)+len(r.projectObjects))
	for _, object := range objects {
		if key := strings.TrimSpace(object.Key); key != "" {
			seen[key] = true
		}
	}
	for _, object := range r.projectObjects {
		key := strings.TrimSpace(object.Key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		objects = append(objects, object)
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].Key < objects[right].Key })
	return objects
}

func (r *MetadataRuntime) SchemaForPrincipal(_ context.Context, principal identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	return metadataservice.SnapshotForPrincipal(r.Schema(), principal)
}

func snapshotState(snapshot metadatamodel.MetadataSchemaSnapshot) metadataservice.SchemaSnapshotState {
	return metadataservice.SchemaSnapshotState{
		TemplateID: snapshot.TemplateID, TemplateVersion: snapshot.TemplateVersion, Name: snapshot.Name,
		Objects: snapshot.Objects, Actions: snapshot.Actions, Roles: snapshot.Roles,
		PermissionSets: snapshot.PermissionSets, PermissionSetGroups: snapshot.PermissionSetGroups,
		Guardrails: snapshot.Guardrails, IdentityProfileExtensions: snapshot.IdentityProfileExtensions,
	}
}
