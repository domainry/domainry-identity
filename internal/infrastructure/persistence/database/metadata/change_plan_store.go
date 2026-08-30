package metadata

import auditmodel "github.com/domainry/domainry-audit-sdk/contract"
import auditmoduleimpl "github.com/domainry/domainry-audit/module"

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s MetadataStore) insertMetadataChangeAudit(ctx context.Context, tx *sql.Tx, event auditmodel.AuditEvent) error {
	return auditmoduleimpl.AppendPreparedWithin(ctx, s.store.BuilderRenderer(), identityauditmodule.NewTransaction(tx), event)
}

func (s MetadataStore) nextMetadataSchemaVersionTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string) (string, error) {
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, "metadata_definition_versions").
		Projections(ormbuilder.Project(ormbuilder.CountAll())).
		Where(ormbuilder.And(ormbuilder.Equal("resource_type", resourceType), ormbuilder.Equal("resource_key", resourceKey))).Build()
	if err != nil {
		return "", fmt.Errorf("build metadata version count query: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
		return "", fmt.Errorf("read metadata version count: %w", err)
	}
	return fmt.Sprintf("%d", count+1), nil
}

func (s MetadataStore) insertMetadataDefinitionVersionTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey, version, hash string, payload []byte, now string) error {
	statement, arguments, err := ormbuilder.NewInsertBuilder(s.store.SQLRenderer, "metadata_definition_versions").
		Columns("id", "resource_type", "resource_key", "schema_version", "schema_hash", "payload_json", "created_at").
		Values(metadataResourceID(resourceType+":version", resourceKey+":"+version+":"+metadataHashPrefix(hash)), resourceType, resourceKey, version, hash, string(payload), now).Build()
	if err != nil {
		return fmt.Errorf("build %s %s version insert: %w", resourceType, resourceKey, err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("insert %s %s version: %w", resourceType, resourceKey, err)
	}
	return nil
}

func (s MetadataStore) currentMetadataHashTx(ctx context.Context, tx *sql.Tx, table, resourceKey string) string {
	var current string
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_hash").Where(ormbuilder.Equal("resource_key", resourceKey)).Build()
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
