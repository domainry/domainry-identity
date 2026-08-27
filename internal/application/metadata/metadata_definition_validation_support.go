package metadata

import (
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"
)

func newMetadataDefinitionValidationIssue(code, fieldPath, stepKey, operationKey string, params map[string]string) metadatamodel.MetadataDefinitionValidationIssue {
	return metadatavalidation.NewMetadataDefinitionValidationIssue(code, fieldPath, stepKey, operationKey, params)
}

func firstMetadataDefinitionIssueError(issues []metadatamodel.MetadataDefinitionValidationIssue) error {
	return metadatavalidation.MetadataFirstDefinitionIssueError(issues)
}

func stringSet(values []string) map[string]bool {
	return metadatavalidation.MetadataStringSet(values)
}

func normalizedDefinitionValue(value any) string {
	return metadatavalidation.MetadataNormalizedDefinitionValue(value)
}
