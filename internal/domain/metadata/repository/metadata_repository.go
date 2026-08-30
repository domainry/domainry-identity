package repository

import (
	"context"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

type MetadataRepository interface {
	SnapshotRevision(ctx context.Context, scope identitymodel.SystemScope) (string, error)
	LoadManifest(ctx context.Context, scope identitymodel.SystemScope) (manifestmodel.ManifestSchema, error)
	SyncManifest(ctx context.Context, scope identitymodel.SystemScope, manifest manifestmodel.ManifestSchema) error
	MigrationPlan(ctx context.Context, scope identitymodel.SystemScope, manifest manifestmodel.ManifestSchema) ([]metadatamodel.MetadataMigrationStep, error)
	PublishDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) (metadatamodel.MetadataDefinition, error)
	CompleteDefinitionRefresh(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey, schemaHash, errorText string) error
	ApplyDefinitionMutations(ctx context.Context, scope identitymodel.SystemScope, mutations []metadatamodel.MetadataDefinitionMutation, audits []auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) ([]metadatamodel.MetadataDefinition, error)
	DisableDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey, expectedSchemaHash string, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) error
	ListDefinitions(ctx context.Context, scope identitymodel.SystemScope, resourceType string) ([]metadatamodel.MetadataDefinition, error)
	GetDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) (metadatamodel.MetadataDefinition, bool, error)
	ListDefinitionVersions(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error)
	RollbackDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionRollbackRequest, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) (metadatamodel.MetadataDefinition, error)
	ListLocalizedTexts(ctx context.Context, workspaceID string, query metadatamodel.LocalizedTextQuery) ([]metadatamodel.LocalizedText, error)
	UpsertLocalizedText(ctx context.Context, workspaceID string, req metadatamodel.LocalizedTextUpsertRequest) (metadatamodel.LocalizedText, error)
}

// DefinitionMutationRepository atomically persists a reviewed definition
// mutation set and its mandatory audit/publication evidence.
type DefinitionMutationRepository interface {
	ApplyDefinitionMutations(context.Context, identitymodel.SystemScope, []metadatamodel.MetadataDefinitionMutation, []auditmodel.AuditEvent, *metadatamodel.MetadataDefinitionPublication) ([]metadatamodel.MetadataDefinition, error)
}
