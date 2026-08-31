package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-metadata-sdk/repository"
	"github.com/domainry/domainry-orm/query"
)

func metadataModuleOwnsDefinition(resourceType string) bool {
	switch strings.TrimSpace(resourceType) {
	case "object", "field", "validation", "action", "dictionary", "role":
		return true
	default:
		return false
	}
}

func (s MetadataStore) countOwnedDefinitionVersions(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey string) (int, error) {
	if strings.TrimSpace(resourceType) == "identity_profile_binding" {
		queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_profile_binding_definition_versions").Projections(query.Project(query.CountAll())).Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey))).Build()
		if err != nil {
			return 0, err
		}
		rows, err := executor.QueryContext(ctx, queryValue, args...)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if !rows.Next() {
			return 0, rows.Err()
		}
		var count int
		return count, rows.Scan(&count)
	}
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return 0, err
	}
	return repository.CountDefinitionVersionsWithExecutor(ctx, executor, resourceType, resourceKey)
}

func (s MetadataStore) insertOwnedDefinitionVersion(ctx context.Context, executor metadatarepository.ExecutionExecutor, value metadatarepository.DefinitionVersion) error {
	if strings.TrimSpace(value.ResourceType) == "identity_profile_binding" {
		id := strings.TrimSpace(value.ResourceType) + ":version:" + strings.TrimSpace(value.ResourceKey) + ":" + strings.TrimSpace(value.SchemaVersion) + ":" + metadataHashPrefix(value.SchemaHash)
		queryValue, args, err := query.NewInsertBuilder(s.store.SQLRenderer, "_identity_profile_binding_definition_versions").Columns("id", "resource_type", "resource_key", "schema_version", "schema_hash", "payload_json", "created_at").Values(id, value.ResourceType, value.ResourceKey, value.SchemaVersion, value.SchemaHash, value.Payload, value.CreatedAt).Build()
		if err != nil {
			return err
		}
		_, err = executor.ExecContext(ctx, queryValue, args...)
		return err
	}
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return err
	}
	return repository.InsertDefinitionVersionWithExecutor(ctx, executor, value)
}

func (s MetadataStore) listOwnedDefinitionVersions(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey string) ([]metadatarepository.DefinitionVersion, error) {
	if strings.TrimSpace(resourceType) == "identity_profile_binding" {
		queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_profile_binding_definition_versions").Columns("schema_version", "schema_hash", "payload_json", "created_at").Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey))).OrderBy(query.Descending("created_at")).Build()
		if err != nil {
			return nil, err
		}
		rows, err := executor.QueryContext(ctx, queryValue, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		values := []metadatarepository.DefinitionVersion{}
		for rows.Next() {
			value := metadatarepository.DefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey}
			var payload string
			if err := rows.Scan(&value.SchemaVersion, &value.SchemaHash, &payload, &value.CreatedAt); err != nil {
				return nil, err
			}
			value.Payload = []byte(payload)
			values = append(values, value)
		}
		return values, rows.Err()
	}
	repository, err := s.metadataModuleDefinitionStore()
	if err != nil {
		return nil, err
	}
	return repository.ListDefinitionVersionsWithExecutor(ctx, executor, resourceType, resourceKey)
}

func (s MetadataStore) getOwnedDefinitionVersion(ctx context.Context, executor metadatarepository.ExecutionExecutor, resourceType, resourceKey, version string) (metadatarepository.DefinitionVersion, bool, error) {
	if strings.TrimSpace(resourceType) == "identity_profile_binding" {
		queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_profile_binding_definition_versions").Columns("schema_hash", "payload_json", "created_at").Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey), query.Equal("schema_version", version))).Build()
		if err != nil {
			return metadatarepository.DefinitionVersion{}, false, err
		}
		rows, err := executor.QueryContext(ctx, queryValue, args...)
		if err != nil {
			return metadatarepository.DefinitionVersion{}, false, err
		}
		defer rows.Close()
		if !rows.Next() {
			return metadatarepository.DefinitionVersion{}, false, rows.Err()
		}
		value := metadatarepository.DefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey, SchemaVersion: version}
		var payload string
		if err := rows.Scan(&value.SchemaHash, &payload, &value.CreatedAt); err != nil {
			return metadatarepository.DefinitionVersion{}, false, err
		}
		value.Payload = []byte(payload)
		return value, true, nil
	}
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
