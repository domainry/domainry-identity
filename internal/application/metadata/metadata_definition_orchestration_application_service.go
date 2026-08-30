package metadata

import (
	"context"

	metadataauthoring "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s *MetadataApplicationService) normalizeAndValidateFieldMetadataMutation(ctx context.Context, req metadatamodel.MetadataDefinitionUpsertRequest) (metadatamodel.MetadataDefinitionUpsertRequest, error) {
	return MetadataNormalizeFieldMutation(ctx, req, s.runtime.Schema().Objects, metadataauthoring.MetadataAuthoringFieldTypes())
}
