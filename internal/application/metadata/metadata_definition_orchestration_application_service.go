package metadata

import (
	"context"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadataauthoring "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s *MetadataApplicationService) normalizeAndValidateFieldMetadataMutation(ctx context.Context, req metadatamodel.MetadataDefinitionUpsertRequest) (metadatamodel.MetadataDefinitionUpsertRequest, error) {
	return MetadataNormalizeFieldMutation(ctx, req, s.runtime.Schema().Objects, metadataauthoring.MetadataAuthoringFieldTypes())
}

// ReferenceGraph is a read-only projection used by human and model clients to
// prepare the same workspace-scoped system draft. Definition mutations are
// intentionally absent from MetadataApplicationService: reviewed Change Plan
// publication is the only production authoring command boundary.
func (s *MetadataApplicationService) ReferenceGraph(ctx context.Context, principal identitymodel.Principal) (changeplanmodel.ReferenceGraph, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return changeplanmodel.ReferenceGraph{}, err
	}
	if s.references == nil {
		return changeplanmodel.ReferenceGraph{}, metadataInternalError("resolve metadata reference graph")
	}
	return s.references.Graph(ctx, principal)
}
