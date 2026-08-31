package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

func (s MetadataStore) insertMetadataChangeAudit(ctx context.Context, tx *sql.Tx, event auditmodel.AuditEvent) error {
	return auditmoduleimpl.AppendPreparedWithin(ctx, s.store.BuilderRenderer(), identityauditmodule.NewTransaction(tx), event)
}

func (s MetadataStore) nextMetadataSchemaVersionTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string) (string, error) {
	count, err := s.countOwnedDefinitionVersions(ctx, tx, resourceType, resourceKey)
	if err != nil {
		return "", fmt.Errorf("read metadata version count: %w", err)
	}
	return fmt.Sprintf("%d", count+1), nil
}

func (s MetadataStore) insertMetadataDefinitionVersionTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey, version, hash string, payload []byte, now string) error {
	err := s.insertOwnedDefinitionVersion(ctx, tx, metadataDefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey, SchemaVersion: version, SchemaHash: hash, Payload: append([]byte(nil), payload...), CreatedAt: now})
	if err != nil {
		return fmt.Errorf("insert %s %s version: %w", resourceType, resourceKey, err)
	}
	return nil
}

func (s MetadataStore) currentMetadataHashTx(ctx context.Context, tx *sql.Tx, table, resourceKey string) string {
	var current string
	statement, arguments, err := query.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_hash").Where(query.Equal("resource_key", resourceKey)).Build()
	if err == nil {
		_ = tx.QueryRowContext(ctx, statement, arguments...).Scan(&current)
	}
	return current
}

func metadataMutationValueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

type metadataDefinitionVersion struct {
	ResourceType  string
	ResourceKey   string
	SchemaVersion string
	SchemaHash    string
	Payload       []byte
	CreatedAt     string
}

func identityDefinitionVersionTable(resourceType string) (string, error) {
	switch strings.TrimSpace(resourceType) {
	case "role":
		return "_identity_role_definition_versions", nil
	case "identity_profile_binding":
		return "_identity_profile_binding_definition_versions", nil
	default:
		return "", fmt.Errorf("Metadata-owned %s definition versions are unavailable from Identity", resourceType)
	}
}

func (s MetadataStore) countOwnedDefinitionVersions(ctx context.Context, executor transaction.Executor, resourceType, resourceKey string) (int, error) {
	table, err := identityDefinitionVersionTable(resourceType)
	if err != nil {
		return 0, err
	}
	queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, table).Projections(query.Project(query.CountAll())).Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey))).Build()
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

func (s MetadataStore) insertOwnedDefinitionVersion(ctx context.Context, executor transaction.Executor, value metadataDefinitionVersion) error {
	table, err := identityDefinitionVersionTable(value.ResourceType)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(value.ResourceType) + ":version:" + strings.TrimSpace(value.ResourceKey) + ":" + strings.TrimSpace(value.SchemaVersion) + ":" + metadataHashPrefix(value.SchemaHash)
	queryValue, args, err := query.NewInsertBuilder(s.store.SQLRenderer, table).Columns("id", "resource_type", "resource_key", "schema_version", "schema_hash", "payload_json", "created_at").Values(id, value.ResourceType, value.ResourceKey, value.SchemaVersion, value.SchemaHash, value.Payload, value.CreatedAt).Build()
	if err != nil {
		return err
	}
	_, err = executor.ExecContext(ctx, queryValue, args...)
	return err
}

func (s MetadataStore) listOwnedDefinitionVersions(ctx context.Context, executor transaction.Executor, resourceType, resourceKey string) ([]metadataDefinitionVersion, error) {
	table, err := identityDefinitionVersionTable(resourceType)
	if err != nil {
		return nil, err
	}
	queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_version", "schema_hash", "payload_json", "created_at").Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey))).OrderBy(query.Descending("created_at")).Build()
	if err != nil {
		return nil, err
	}
	rows, err := executor.QueryContext(ctx, queryValue, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []metadataDefinitionVersion{}
	for rows.Next() {
		value := metadataDefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey}
		var payload string
		if err := rows.Scan(&value.SchemaVersion, &value.SchemaHash, &payload, &value.CreatedAt); err != nil {
			return nil, err
		}
		value.Payload = []byte(payload)
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s MetadataStore) getOwnedDefinitionVersion(ctx context.Context, executor transaction.Executor, resourceType, resourceKey, version string) (metadataDefinitionVersion, bool, error) {
	table, err := identityDefinitionVersionTable(resourceType)
	if err != nil {
		return metadataDefinitionVersion{}, false, err
	}
	queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_hash", "payload_json", "created_at").Where(query.And(query.Equal("resource_type", resourceType), query.Equal("resource_key", resourceKey), query.Equal("schema_version", version))).Build()
	if err != nil {
		return metadataDefinitionVersion{}, false, err
	}
	rows, err := executor.QueryContext(ctx, queryValue, args...)
	if err != nil {
		return metadataDefinitionVersion{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return metadataDefinitionVersion{}, false, rows.Err()
	}
	value := metadataDefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey, SchemaVersion: version}
	var payload string
	if err := rows.Scan(&value.SchemaHash, &payload, &value.CreatedAt); err != nil {
		return metadataDefinitionVersion{}, false, err
	}
	value.Payload = []byte(payload)
	return value, true, nil
}
