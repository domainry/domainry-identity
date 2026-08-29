package schema

import (
	"context"
	"fmt"
)

// EnsureEvidenceSchema owns Identity's immutable audit evidence.
func EnsureEvidenceSchema(ctx context.Context, s Store) error {
	text := s.MetadataIDColumnType()
	cursorText := s.SchemaTypes().AuditCursorText
	tables := map[string][]string{
		"_audit_events": auditEventColumnDefinitions(text, cursorText),
	}
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+quotedColumnDefinitions(s, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	if err := prepareAuditEventWorkspace(ctx, s, text); err != nil {
		return err
	}
	if err := ensureMySQLAuditCursorColumns(ctx, s); err != nil {
		return err
	}
	if err := s.CreateIndexIfMissing(ctx, "_audit_events", "idx_audit_event_actor_cursor", false, auditEventActorCursorColumns()...); err != nil {
		return fmt.Errorf("create audit actor cursor index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_audit_events", "idx_audit_event_record_cursor", false, auditEventRecordCursorColumns()...); err != nil {
		return fmt.Errorf("create audit record cursor index: %w", err)
	}
	return nil
}

// RemoveFrontendCapabilityRegistry retires the old deployment-evidence table.
// Identity administration visibility is derived from menus and effective
// permissions; it is not registered by a static frontend manifest.
func RemoveFrontendCapabilityRegistry(ctx context.Context, s Store) error {
	if _, err := s.SchemaDB().ExecContext(ctx, "DROP TABLE IF EXISTS "+s.TableIdentifier("frontend_capability_manifests")); err != nil {
		return fmt.Errorf("remove retired frontend capability registry: %w", err)
	}
	return nil
}

func auditEventColumnDefinitions(text, cursorText string) []string {
	return []string{
		"id " + cursorText + " PRIMARY KEY",
		"workspace_id " + text + " NOT NULL",
		"event " + text + " NOT NULL",
		"object_key " + text,
		"record_id " + text,
		"actor_id " + text,
		"role_key " + text,
		"summary TEXT",
		"metadata_json TEXT NOT NULL",
		"before_json TEXT NOT NULL",
		"after_json TEXT NOT NULL",
		"created_at " + cursorText + " NOT NULL",
	}
}
