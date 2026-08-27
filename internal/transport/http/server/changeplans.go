package httpserver

import (
	"context"
	"net/http"

	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	changeplanapplication "github.com/domainry/domainry-identity/internal/application/changeplan"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	metadataapplication "github.com/domainry/domainry-identity/internal/application/metadata"
	"github.com/domainry/domainry-identity/internal/assembly"
	changeplancontract "github.com/domainry/domainry-identity/internal/domain/changeplan/contract"
	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	changeplanprojection "github.com/domainry/domainry-identity/internal/domain/changeplan/projection"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"
)

// identityChangePlanProjection provides the immutable authoring snapshot and
// reference graph needed by the Admin console. It projects Identity metadata;
// it does not start or call the Plane business Runtime.
type identityChangePlanProjection struct {
	runtime      *assembly.MetadataRuntime
	metadata     *metadataapplication.MetadataApplicationService
	identity     *identityapplication.IdentityApplicationService
	capabilities *identityauthoring.AuthoringCatalog
	support      *httpSupport
}

func newIdentityChangePlanProjection(
	runtime *assembly.MetadataRuntime,
	metadata *metadataapplication.MetadataApplicationService,
	identity *identityapplication.IdentityApplicationService,
	capabilities *identityauthoring.AuthoringCatalog,
	support *httpSupport,
) *identityChangePlanProjection {
	return &identityChangePlanProjection{
		runtime: runtime, metadata: metadata,
		identity: identity, capabilities: capabilities, support: support,
	}
}

func (p *identityChangePlanProjection) snapshotSource(r *http.Request) (changeplancontract.SnapshotSource, error) {
	return p.snapshot(r)
}

func (p *identityChangePlanProjection) graphSource(r *http.Request) (changeplancontract.ReferenceGraphSource, error) {
	return p.graph(r)
}

func (p *identityChangePlanProjection) snapshot(r *http.Request) (changeplanprojection.BusinessSystemSnapshot, error) {
	principal := p.support.principal(r)
	schema := p.runtime.SchemaForPrincipal(r.Context(), principal)
	governance, err := p.identity.GovernanceSnapshot(r.Context(), principal)
	if err != nil {
		return changeplanprojection.BusinessSystemSnapshot{}, err
	}
	authoring := p.capabilities.Contract(identityCapabilityInstance(schema, p.identity.PermissionDefinitions()))
	snapshot := changeplanprojection.BusinessSystemSnapshot{
		SnapshotVersion:          changeplanprojection.BusinessSystemSnapshotVersion,
		RuntimeVersion:           authoring.RuntimeVersion,
		AuthoringContractVersion: authoring.ContractVersion,
		AuthoringContractHash:    authoring.ContractHash,
		SchemaHash:               schema.SchemaHash,
		Schema:                   schema,
		ResourceSources:          []changeplanprojection.SystemResourceSource{},
		ObjectRecordCounts:       map[string]int{},
		CapabilityKeys:           p.capabilities.Keys(),
	}
	for _, resourceType := range metadatavalidation.MetadataBusinessResourceTypes() {
		definitions, listErr := p.metadata.ListMetadataDefinitions(r.Context(), resourceType, principal.WorkspaceID, principal)
		if listErr != nil {
			return changeplanprojection.BusinessSystemSnapshot{}, listErr
		}
		for _, definition := range definitions {
			snapshot.ResourceSources = append(snapshot.ResourceSources, changeplanprojection.SystemResourceSource{
				ResourceType: definition.ResourceType, ResourceKey: definition.ResourceKey,
				ObjectKey: definition.ObjectKey, Name: definition.Name,
				SchemaVersion: definition.SchemaVersion, SchemaHash: definition.SchemaHash,
				SourceKind: definition.SourceKind, SourceID: definition.SourceID,
				Disabled: definition.DisabledAt != "",
			})
		}
	}
	snapshot = snapshot.WithIdentityGovernance(governance)
	snapshot.Finalize()
	return snapshot, nil
}

func (p *identityChangePlanProjection) graph(r *http.Request) (changeplanmodel.ReferenceGraph, error) {
	principal := p.support.principal(r)
	references := changeplanapplication.NewChangePlanReferenceApplicationService(
		func(ctx context.Context, principal identitymodel.Principal) changeplanapplication.ReferenceSchema {
			schema := p.runtime.SchemaForPrincipal(ctx, principal)
			return changeplanapplication.ReferenceSchema{
				Objects: schema.Objects, Views: schema.Views, Actions: schema.Actions,
				Roles: schema.Roles, ProfileBindings: schema.IdentityProfileExtensions,
			}
		},
	)
	graph, err := references.Graph(r.Context(), principal)
	if err != nil {
		return changeplanmodel.ReferenceGraph{}, err
	}
	return p.identity.EnrichBusinessReferenceGraph(r.Context(), graph, principal)
}

func (p *identityChangePlanProjection) systemSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := p.snapshot(r)
	if err != nil {
		p.support.writeServiceError(w, r, err)
		return
	}
	p.support.writeJSON(w, http.StatusOK, snapshot)
}

func (p *identityChangePlanProjection) referenceGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := p.graph(r)
	if err != nil {
		p.support.writeServiceError(w, r, err)
		return
	}
	p.support.writeJSON(w, http.StatusOK, graph)
}

type metadataChangePlanRuntime struct {
	metadata *metadataapplication.MetadataApplicationService
}

func (r metadataChangePlanRuntime) CanonicalizeMetadataCandidate(ctx context.Context, mutations []metadatamodel.MetadataDefinitionMutation) ([]metadatamodel.MetadataDefinitionMutation, error) {
	return r.metadata.CanonicalizeMetadataCandidate(ctx, mutations)
}

func (r metadataChangePlanRuntime) ReloadMetadata(ctx context.Context, principal identitymodel.Principal) (string, error) {
	snapshot, err := r.metadata.ReloadMetadata(ctx, principal)
	return snapshot.SchemaHash, err
}
