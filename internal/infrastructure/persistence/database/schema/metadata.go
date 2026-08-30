package schema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// EnsureMetadataSchema creates only the definition storage used by the
// Identity Admin metadata editor. Business-runtime, notification, scheduler,
// workflow and integration tables deliberately do not belong to this service.
func EnsureMetadataSchema(ctx context.Context, s Store) error {
	documentText := s.SchemaTypes().DocumentText
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("application_schema_catalog")+" ("+
		s.Identifier("key")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
		s.Identifier("value")+" "+documentText+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create application_schema_catalog: %w", err)
	}
	if err := migrateLegacyIdentityMetadataTables(ctx, s); err != nil {
		return err
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("identity_metadata_refresh_intents")+" ("+
		s.Identifier("id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("workspace_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("owner")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("operation")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("resource_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("idempotency_key")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("status")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("payload_json")+" "+documentText+" NOT NULL, "+
		s.Identifier("compensation_payload_json")+" "+documentText+" NOT NULL, "+
		s.Identifier("attempt_count")+" INTEGER NOT NULL DEFAULT 0, "+
		s.Identifier("next_attempt_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("lease_owner")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("lease_expires_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("fencing_token")+" BIGINT NOT NULL DEFAULT 0, "+
		s.Identifier("last_error")+" "+documentText+" NOT NULL, "+
		s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		"PRIMARY KEY ("+s.Identifier("workspace_id")+", "+s.Identifier("id")+"))"); err != nil {
		return fmt.Errorf("create identity_metadata_refresh_intents: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_metadata_refresh_intents", "uniq_identity_metadata_refresh_intent_key", true, "workspace_id", "owner", "operation", "resource_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity metadata refresh intent key: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_metadata_refresh_intents", "idx_identity_metadata_refresh_intent_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create identity metadata refresh intent lease: %w", err)
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("identity_localized_text")+" ("+
		s.Identifier("id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("workspace_id")+" "+s.LocalizedTextKeyColumnType()+" NOT NULL, "+
		s.Identifier("entity_type")+" "+s.LocalizedTextKeyColumnType()+" NOT NULL, "+
		s.Identifier("entity_key")+" "+s.LocalizedTextKeyColumnType()+" NOT NULL, "+
		s.Identifier("property")+" "+s.LocalizedTextKeyColumnType()+" NOT NULL, "+
		s.Identifier("locale")+" "+s.LocalizedTextKeyColumnType()+" NOT NULL, "+
		s.Identifier("text")+" TEXT NOT NULL, "+
		s.Identifier("source_kind")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("source_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create identity_localized_text: %w", err)
	}
	for _, index := range []struct {
		name    string
		unique  bool
		columns []string
	}{
		{name: "uniq_identity_localized_text_key", unique: true, columns: []string{"workspace_id", "entity_type", "entity_key", "property", "locale"}},
		{name: "uniq_identity_localized_text_workspace_identity", unique: true, columns: []string{"workspace_id", "id"}},
		{name: "idx_identity_localized_text_entity", columns: []string{"entity_type", "entity_key"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, "identity_localized_text", index.name, index.unique, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	return nil
}

func migrateLegacyIdentityMetadataTables(ctx context.Context, s Store) error {
	// domainry-orm has no INSERT ... SELECT or DROP TABLE builder. These bounded,
	// dialect-neutral statements preserve legacy rows while ownership is split.
	if exists, err := s.SchemaTableExists(ctx, "metadata_catalog"); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("inspect legacy metadata_catalog: %w", err)
	} else if exists {
		columns := quotedIdentityMetadataMigrationColumns(s, []string{"key", "value", "updated_at"})
		key := s.Identifier("key")
		if _, err := s.SchemaDB().ExecContext(ctx, "DELETE FROM "+s.TableIdentifier("application_schema_catalog")+" WHERE "+key+" IN (SELECT "+key+" FROM "+s.TableIdentifier("metadata_catalog")+")"); err != nil {
			return fmt.Errorf("prepare metadata_catalog copy: %w", err)
		}
		if _, err := s.SchemaDB().ExecContext(ctx, "INSERT INTO "+s.TableIdentifier("application_schema_catalog")+" ("+columns+") SELECT "+columns+" FROM "+s.TableIdentifier("metadata_catalog")); err != nil {
			return fmt.Errorf("copy metadata_catalog: %w", err)
		}
		if _, err := s.SchemaDB().ExecContext(ctx, "DROP TABLE "+s.TableIdentifier("metadata_catalog")); err != nil {
			return fmt.Errorf("retire metadata_catalog: %w", err)
		}
	}
	exists, err := s.SchemaTableExists(ctx, "identity_definition_versions")
	if errors.Is(err, sql.ErrNoRows) {
		exists, err = false, nil
	}
	if err != nil {
		return err
	}
	if exists {
		columns := quotedIdentityMetadataMigrationColumns(s, []string{"id", "resource_type", "resource_key", "schema_version", "schema_hash", "payload_json", "created_at"})
		id := s.Identifier("id")
		if _, err := s.SchemaDB().ExecContext(ctx, "DELETE FROM "+s.TableIdentifier("metadata_definition_versions")+" WHERE "+id+" IN (SELECT "+id+" FROM "+s.TableIdentifier("identity_definition_versions")+")"); err != nil {
			return fmt.Errorf("prepare Identity definition version consolidation: %w", err)
		}
		if _, err := s.SchemaDB().ExecContext(ctx, "INSERT INTO "+s.TableIdentifier("metadata_definition_versions")+" ("+columns+") SELECT "+columns+" FROM "+s.TableIdentifier("identity_definition_versions")); err != nil {
			return fmt.Errorf("consolidate Identity definition versions: %w", err)
		}
		if _, err := s.SchemaDB().ExecContext(ctx, "DROP TABLE "+s.TableIdentifier("identity_definition_versions")); err != nil {
			return fmt.Errorf("retire Identity definition version table: %w", err)
		}
	}
	moduleVersionsExist, err := s.SchemaTableExists(ctx, "metadata_definition_versions")
	if errors.Is(err, sql.ErrNoRows) {
		moduleVersionsExist, err = false, nil
	}
	if err != nil {
		return err
	}
	if moduleVersionsExist {
		if _, err := s.SchemaDB().ExecContext(ctx, "DELETE FROM "+s.TableIdentifier("metadata_definition_versions")+" WHERE "+s.Identifier("resource_type")+" = "+s.Placeholder(1), "view"); err != nil {
			return fmt.Errorf("retire view definition versions: %w", err)
		}
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "DROP TABLE IF EXISTS "+s.TableIdentifier("view_definitions")); err != nil {
		return fmt.Errorf("retire view definitions: %w", err)
	}
	return nil
}

func quotedIdentityMetadataMigrationColumns(s Store, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = s.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
