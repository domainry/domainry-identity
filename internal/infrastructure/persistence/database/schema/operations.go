package schema

import (
	"context"
	"fmt"
)

func OperationsKernelTables() []string {
	return []string{"_operation_controls", "_operations"}
}

// EnsureOperationsSchema installs the shared Operations kernel in an
// Identity-owned SaaS database. Embedded Identity deliberately skips this
// function because Runtime owns the same physical tables in the borrowed
// project database.
func EnsureOperationsSchema(ctx context.Context, s Store) error {
	text := s.MetadataIDColumnType()
	indexedText := s.SchemaTypes().IndexedText
	tables := map[string][]string{
		"_operations": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + indexedText + " NOT NULL",
			"system_purpose " + indexedText + " NOT NULL DEFAULT ''",
			"owner " + indexedText + " NOT NULL",
			"kind " + indexedText + " NOT NULL",
			"action_key " + text + " NOT NULL",
			"parent_id " + text + " NOT NULL DEFAULT ''",
			"resource_type " + text + " NOT NULL",
			"resource_id " + text + " NOT NULL DEFAULT ''",
			"idempotency_key " + indexedText + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"requested_by " + text + " NOT NULL",
			"reason TEXT NOT NULL",
			"reference " + text + " NOT NULL DEFAULT ''",
			"status " + indexedText + " NOT NULL",
			"status_url TEXT NOT NULL",
			"result_json TEXT NOT NULL",
			"metadata_json TEXT NOT NULL",
			"error_code " + text + " NOT NULL DEFAULT ''",
			"failure_class " + text + " NOT NULL DEFAULT ''",
			"next_action TEXT NOT NULL DEFAULT ''",
			"related_ids_json TEXT NOT NULL",
			"correlation " + text + " NOT NULL DEFAULT ''",
			"evidence_json TEXT NOT NULL",
			"lease_owner " + text + " NOT NULL DEFAULT ''",
			"lease_expires_at " + indexedText + " NOT NULL DEFAULT ''",
			"fencing_token BIGINT NOT NULL DEFAULT 0",
			"expires_at " + indexedText + " NOT NULL DEFAULT ''",
			"created_at " + indexedText + " NOT NULL",
			"started_at " + text + " NOT NULL DEFAULT ''",
			"finished_at " + text + " NOT NULL DEFAULT ''",
			"updated_at " + text + " NOT NULL",
		},
		"_operation_controls": {
			"system_purpose " + indexedText + " NOT NULL",
			"control_kind " + indexedText + " NOT NULL",
			"owner " + indexedText + " NOT NULL",
			"state " + indexedText + " NOT NULL",
			"reason TEXT NOT NULL",
			"reference " + text + " NOT NULL DEFAULT ''",
			"updated_by " + text + " NOT NULL",
			"revision BIGINT NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
	}
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+quotedColumnDefinitions(s, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	for _, index := range []struct {
		table   string
		name    string
		unique  bool
		columns []string
	}{
		{table: "_operations", name: "uniq_runtime_operation_key", unique: true, columns: []string{"workspace_id", "system_purpose", "owner", "kind", "idempotency_key"}},
		{table: "_operations", name: "idx_runtime_operation_status", columns: []string{"workspace_id", "owner", "status", "created_at"}},
		{table: "_operations", name: "idx_runtime_operation_parent", columns: []string{"workspace_id", "parent_id", "created_at"}},
		{table: "_operations", name: "idx_runtime_operation_lease", columns: []string{"owner", "status", "lease_expires_at"}},
		{table: "_operation_controls", name: "uniq_runtime_operation_control", unique: true, columns: []string{"system_purpose", "control_kind", "owner"}},
		{table: "_operation_controls", name: "idx_runtime_operation_control_state", columns: []string{"system_purpose", "control_kind", "state"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, index.table, index.name, index.unique, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	return nil
}
