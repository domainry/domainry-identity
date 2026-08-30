package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	metadatarepository "github.com/domainry/domainry-metadata-sdk/repository"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s MetadataStore) insertMetadataResource(ctx context.Context, tx *sql.Tx, seed metadataResourceSeed, now string) error {
	raw, hash, err := metadataPayload(seed.Payload)
	if err != nil {
		return fmt.Errorf("encode %s %s: %w", seed.ResourceType, seed.Key, err)
	}
	values := []any{
		metadataResourceID(seed.ResourceType, seed.Key),
		seed.Key,
		seed.ObjectKey,
		seed.Name,
		string(raw),
		seed.SchemaVersion,
		hash,
		seed.SourceKind,
		seed.SourceID,
		nil,
		now,
		now,
	}
	statement, arguments, err := ormbuilder.NewInsertBuilder(s.store.SQLRenderer, seed.Table).
		Columns("id", "resource_key", "object_key", "name", "payload_json", "schema_version", "schema_hash", "source_kind", "source_id", "disabled_at", "created_at", "updated_at").
		Values(values...).Build()
	if err != nil {
		return fmt.Errorf("build %s %s insert: %w", seed.ResourceType, seed.Key, err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("insert %s %s: %w", seed.ResourceType, seed.Key, err)
	}
	if err := s.insertOwnedDefinitionVersion(ctx, tx, metadatarepository.DefinitionVersion{
		ResourceType: seed.ResourceType, ResourceKey: seed.Key, SchemaVersion: seed.SchemaVersion,
		SchemaHash: hash, Payload: raw, CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("insert %s %s version: %w", seed.ResourceType, seed.Key, err)
	}
	return nil
}

func (s MetadataStore) syncMetadataResource(ctx context.Context, tx *sql.Tx, seed metadataResourceSeed, now string) error {
	raw, hash, err := metadataPayload(seed.Payload)
	if err != nil {
		return fmt.Errorf("encode %s %s: %w", seed.ResourceType, seed.Key, err)
	}
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, seed.Table).
		Columns("schema_hash", "source_kind", "disabled_at").Where(ormbuilder.Equal("resource_key", seed.Key)).Build()
	if err != nil {
		return fmt.Errorf("build %s %s sync query: %w", seed.ResourceType, seed.Key, err)
	}
	var currentHash string
	var sourceKind string
	var disabledAt sql.NullString
	err = tx.QueryRowContext(ctx, statement, arguments...).Scan(&currentHash, &sourceKind, &disabledAt)
	if err == sql.ErrNoRows {
		return s.insertMetadataResource(ctx, tx, seed, now)
	}
	if err != nil {
		return fmt.Errorf("read %s %s for sync: %w", seed.ResourceType, seed.Key, err)
	}
	if strings.TrimSpace(sourceKind) != "generated" || disabledAt.Valid {
		return nil
	}
	if currentHash == hash {
		return nil
	}
	statement, arguments, err = ormbuilder.NewUpdateBuilder(s.store.SQLRenderer, seed.Table).
		Set("object_key", seed.ObjectKey).Set("name", seed.Name).Set("payload_json", string(raw)).Set("schema_version", seed.SchemaVersion).
		Set("schema_hash", hash).Set("source_id", seed.SourceID).Set("updated_at", now).Where(ormbuilder.Equal("resource_key", seed.Key)).Build()
	if err != nil {
		return fmt.Errorf("build %s %s sync update: %w", seed.ResourceType, seed.Key, err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("sync %s %s: %w", seed.ResourceType, seed.Key, err)
	}
	existing, found, err := s.getOwnedDefinitionVersion(ctx, tx, seed.ResourceType, seed.Key, seed.SchemaVersion)
	if err != nil {
		return fmt.Errorf("read synced %s %s version: %w", seed.ResourceType, seed.Key, err)
	}
	if found {
		if existing.SchemaHash == hash {
			return nil
		}
		return fmt.Errorf("metadata definition version id collision for %s %s", seed.ResourceType, seed.Key)
	}
	if err := s.insertOwnedDefinitionVersion(ctx, tx, metadatarepository.DefinitionVersion{
		ResourceType: seed.ResourceType, ResourceKey: seed.Key, SchemaVersion: seed.SchemaVersion,
		SchemaHash: hash, Payload: raw, CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("insert synced %s %s version: %w", seed.ResourceType, seed.Key, err)
	}
	return nil
}
