package schema

import (
	"context"
	"fmt"
)

// EnsureMetadataSchema creates only the definition storage used by the
// Identity Admin metadata editor. Business-runtime, notification, scheduler,
// workflow and integration tables deliberately do not belong to this service.
func EnsureMetadataSchema(ctx context.Context, s Store) error {
	documentText := s.SchemaTypes().DocumentText
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("metadata_catalog")+" ("+
		s.Identifier("key")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
		s.Identifier("value")+" "+documentText+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create metadata_catalog: %w", err)
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("metadata_definition_versions")+" ("+
		s.Identifier("id")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
		s.Identifier("resource_type")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("resource_key")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("schema_version")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("schema_hash")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("payload_json")+" "+documentText+" NOT NULL, "+
		s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create metadata_definition_versions: %w", err)
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("identity_change_plan_drafts")+" ("+
		s.Identifier("workspace_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("plan_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("revision")+" INTEGER NOT NULL, "+
		s.Identifier("status")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("payload_json")+" "+documentText+" NOT NULL, "+
		s.Identifier("created_by")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("updated_by")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		"PRIMARY KEY ("+s.Identifier("workspace_id")+", "+s.Identifier("plan_id")+"))"); err != nil {
		return fmt.Errorf("create identity_change_plan_drafts: %w", err)
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("identity_change_plan_operations")+" ("+
		s.Identifier("id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("workspace_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("plan_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("plan_revision")+" INTEGER NOT NULL, "+
		s.Identifier("operation")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("idempotency_key")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("request_fingerprint")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("status")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("result_json")+" "+documentText+" NOT NULL, "+
		s.Identifier("lease_owner")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("lease_expires_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("fencing_token")+" BIGINT NOT NULL, "+
		s.Identifier("error_code")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("expires_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("actor_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create identity_change_plan_operations: %w", err)
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
	if err := prepareIdempotencyReceiptMigrations(ctx, s, idempotencyReceiptMigrationSpec{table: "identity_change_plan_operations", scopeColumns: []string{"plan_id", "plan_revision", "operation"}, backfillColumns: []string{"plan_id", "operation"}}); err != nil {
		return err
	}
	for _, index := range []struct {
		name    string
		unique  bool
		columns []string
	}{
		{name: "uniq_change_plan_operation_workspace_identity", unique: true, columns: []string{"workspace_id", "id"}},
		{name: "uniq_change_plan_operation_scope", unique: true, columns: []string{"workspace_id", "plan_id", "plan_revision", "operation", "idempotency_key"}},
		{name: "idx_change_plan_operation_lease", columns: []string{"status", "lease_expires_at"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, "identity_change_plan_operations", index.name, index.unique, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	for _, table := range metadataDefinitionTables() {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+
			s.Identifier("id")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
			s.Identifier("resource_key")+" "+s.MetadataIDColumnType()+" NOT NULL UNIQUE, "+
			s.Identifier("object_key")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("name")+" TEXT NOT NULL, "+
			s.Identifier("payload_json")+" "+documentText+" NOT NULL, "+
			s.Identifier("schema_version")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("schema_hash")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("source_kind")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("source_id")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("disabled_at")+" "+s.MetadataIDColumnType()+", "+
			s.Identifier("created_at")+" "+s.MetadataIDColumnType()+" NOT NULL, "+
			s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
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

func metadataDefinitionTables() []string {
	return []string{
		"object_definitions",
		"field_definitions",
		"validation_definitions",
		"view_definitions",
		"action_definitions",
		"role_definitions",
		"identity_profile_binding_definitions",
	}
}
