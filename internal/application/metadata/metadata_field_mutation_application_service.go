package metadata

import (
	"context"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"
)

// MetadataNormalizeFieldMutation validates Identity's schema catalog. The
// standalone service intentionally does not inspect or mutate host business
// records; Runtime integrations own their data-compatibility preflight.
func MetadataNormalizeFieldMutation(_ context.Context, request metadatamodel.MetadataDefinitionUpsertRequest, objects []definitionmodel.ObjectSchema, allowedFieldTypes []string) (metadatamodel.MetadataDefinitionUpsertRequest, error) {
	return metadatavalidation.MetadataNormalizeFieldMutation(request, objects, allowedFieldTypes, 0)
}
