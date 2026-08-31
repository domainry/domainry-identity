package metadata

import auditmodel "github.com/domainry/domainry-audit-sdk/contract"
import auditmoduleimpl "github.com/domainry/domainry-audit/module"

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	metadatarepository "github.com/domainry/domainry-metadata-sdk/repository"
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
	err := s.insertOwnedDefinitionVersion(ctx, tx, metadatarepository.DefinitionVersion{ResourceType: resourceType, ResourceKey: resourceKey, SchemaVersion: version, SchemaHash: hash, Payload: append([]byte(nil), payload...), CreatedAt: now})
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
