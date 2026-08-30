package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-metadata-sdk/repository"
)

func metadataModuleOwnsDefinition(resourceType string) bool {
	switch strings.TrimSpace(resourceType) {
	case "object", "field", "validation", "action", "dictionary", "role", "identity_profile_binding":
		return true
	default:
		return false
	}
}

func (s MetadataStore) countOwnedDefinitionVersions(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey string) (int, error) {
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return 0, err
	}
	return repository.CountDefinitionVersionsWithExecutor(ctx, executor, resourceType, resourceKey)
}

func (s MetadataStore) insertOwnedDefinitionVersion(ctx context.Context, executor metadatarepository.ExecutionExecutor, value metadatarepository.DefinitionVersion) error {
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return err
	}
	return repository.InsertDefinitionVersionWithExecutor(ctx, executor, value)
}

func (s MetadataStore) listOwnedDefinitionVersions(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey string) ([]metadatarepository.DefinitionVersion, error) {
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return nil, err
	}
	return repository.ListDefinitionVersionsWithExecutor(ctx, executor, resourceType, resourceKey)
}

func (s MetadataStore) getOwnedDefinitionVersion(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey, version string) (metadatarepository.DefinitionVersion, bool, error) {
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return metadatarepository.DefinitionVersion{}, false, err
	}
	return repository.GetDefinitionVersionWithExecutor(ctx, executor, resourceType, resourceKey, version)
}

func (s MetadataStore) metadataModuleDefinitionStore() (metadatarepository.ExecutorDefinitionRepository, error) {
	repository, ok := s.store.MetadataDefinitions().(metadatarepository.ExecutorDefinitionRepository)
	if !ok {
		return nil, fmt.Errorf("Metadata executor definition repository is unavailable")
	}
	return repository, nil
}

func metadataDefinitionFromModule(value metadatarepository.StoredDefinition) metadatamodel.MetadataDefinition {
	return metadatamodel.MetadataDefinition{
		ResourceType: value.ResourceType, ResourceKey: value.Key, ObjectKey: value.ObjectKey, Name: value.Name,
		Payload: append([]byte(nil), value.Payload...), SchemaVersion: value.SchemaVersion, SchemaHash: value.SchemaHash,
		SourceKind: value.SourceKind, SourceID: value.SourceID, DisabledAt: value.DisabledAt,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func (s MetadataStore) replaceMetadataModuleDefinitionTx(ctx context.Context, tx *sql.Tx, value metadatamodel.MetadataDefinition, expectedHash *string) error {
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return err
	}
	result, err := repository.ReplaceDefinitionWithExecutor(ctx, tx, metadatarepository.StoredDefinition{
		Definition:    metadatarepository.Definition{ResourceType: value.ResourceType, Key: value.ResourceKey, ObjectKey: value.ObjectKey, Name: value.Name, Payload: append([]byte(nil), value.Payload...), SchemaHash: value.SchemaHash},
		SchemaVersion: value.SchemaVersion, SourceKind: value.SourceKind, SourceID: value.SourceID, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}, expectedHash)
	if err != nil {
		return fmt.Errorf("replace %s %s: %w", value.ResourceType, value.ResourceKey, err)
	}
	if !result.Replaced {
		expected := ""
		if expectedHash != nil {
			expected = strings.TrimSpace(*expectedHash)
		}
		return &metadatamodel.MetadataDefinitionConflictError{ResourceType: value.ResourceType, ResourceKey: value.ResourceKey, ExpectedHash: expected, CurrentHash: result.CurrentHash}
	}
	return nil
}
