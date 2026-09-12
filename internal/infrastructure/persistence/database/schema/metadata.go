package schema

import (
	"context"
	"fmt"
	ormschema "github.com/domainry/domainry-orm/schema"
)

// EnsureMetadataSchema creates only the definition storage used by the
// Identity Admin metadata editor. Business-runtime, notification, scheduler,
// workflow and integration tables deliberately do not belong to this service.
func EnsureMetadataSchema(ctx context.Context, s Store) error {
	documentText := s.SchemaTypes().DocumentText
	// These baseline tables require engine-provided physical key/document types.
	// domainry-orm has no custom ColumnType for those exact definitions.
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("_identity_manifest_catalog")+" ("+
		s.Identifier("key")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
		s.Identifier("value")+" "+documentText+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create _identity_manifest_catalog: %w", err)
	}
	// The five-column receipt index must fit MySQL's 3072-byte limit under
	// utf8mb4. Owner/operation are internal vocabulary; the idempotency key is
	// a numeric schema version plus a SHA-256 digest. Existing tables are kept.
	statement, arguments, err := ormschema.NewTable(s.SchemaRenderer(), "_identity_metadata_refresh_intents").IfNotExists().Columns(
		ormschema.Column("id", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("workspace_id", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("owner", ormschema.TextKey(32)).NotNull(),
		ormschema.Column("operation", ormschema.TextKey(32)).NotNull(),
		ormschema.Column("resource_id", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("idempotency_key", ormschema.TextKey(128)).NotNull(),
		ormschema.Column("status", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("payload_json", ormschema.LongText()).NotNull(),
		ormschema.Column("compensation_payload_json", ormschema.LongText()).NotNull(),
		ormschema.Column("attempt_count", ormschema.Integer()).NotNull().DefaultValue(0),
		ormschema.Column("next_attempt_at", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("lease_owner", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("lease_expires_at", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("fencing_token", ormschema.BigInt()).NotNull().DefaultValue(0),
		ormschema.Column("last_error", ormschema.LongText()).NotNull(),
		ormschema.Column("created_at", ormschema.TextKey(255)).NotNull(),
		ormschema.Column("updated_at", ormschema.TextKey(255)).NotNull(),
	).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return fmt.Errorf("build metadata refresh intent table: %w", err)
	}
	if _, err = s.SchemaDB().ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create _identity_metadata_refresh_intents: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_metadata_refresh_intents", "uniq_identity_metadata_refresh_intent_key", true, "workspace_id", "owner", "operation", "resource_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity metadata refresh intent key: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_metadata_refresh_intents", "idx_identity_metadata_refresh_intent_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create identity metadata refresh intent lease: %w", err)
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("_identity_localized_texts")+" ("+
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
		return fmt.Errorf("create _identity_localized_texts: %w", err)
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
		if err := s.CreateIndexIfMissing(ctx, "_identity_localized_texts", index.name, index.unique, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	return nil
}
