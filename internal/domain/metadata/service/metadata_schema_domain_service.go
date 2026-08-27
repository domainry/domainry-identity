package service

import (
	"context"

	"github.com/domainry/domainry-foundation/collection"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
)

type CapabilityAuthoringSchemaProvider interface {
	SchemaForPrincipal(context.Context, identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot
}

// MetadataSchemaDomainService owns read-only schema and permission projections.
// Its dependency is the immutable snapshot contract, not RuntimeServices state.
// MetadataSchemaDomainService exposes the current authoring schema.
type MetadataSchemaDomainService struct {
	schema   CapabilityAuthoringSchemaProvider
	metadata metadatarepository.MetadataRepository
}

func NewMetadataSchemaDomainService(schema CapabilityAuthoringSchemaProvider, metadata metadatarepository.MetadataRepository) *MetadataSchemaDomainService {
	return &MetadataSchemaDomainService{schema: schema, metadata: metadata}
}

func (s *MetadataSchemaDomainService) Snapshot(ctx context.Context) metadatamodel.MetadataSchemaSnapshot {
	return s.schema.SchemaForPrincipal(ctx, identitymodel.Principal{})
}

func (s *MetadataSchemaDomainService) ForPrincipal(ctx context.Context, principal identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	return s.schema.SchemaForPrincipal(ctx, principal)
}

func (s *MetadataSchemaDomainService) ObjectMap(ctx context.Context) map[string]definitionmodel.ObjectSchema {
	return collection.IndexBy(s.Snapshot(ctx).Objects, func(object definitionmodel.ObjectSchema) string { return object.Key })
}
