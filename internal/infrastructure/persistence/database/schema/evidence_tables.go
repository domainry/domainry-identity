package schema

import (
	"context"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func prepareAuditEventWorkspace(ctx context.Context, s Store, text string) error {
	if err := s.EnsureColumn(ctx, "_audit_events", "workspace_id", text); err != nil {
		return err
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "UPDATE "+s.TableIdentifier("_audit_events")+" SET "+s.Identifier("workspace_id")+" = COALESCE(NULLIF("+s.Identifier("workspace_id")+", ''), "+s.Placeholder(1)+")", identitymodel.InstallationWorkspaceID); err != nil {
		return fmt.Errorf("backfill audit event workspace: %w", err)
	}
	return nil
}

func auditEventActorCursorColumns() []string {
	return []string{"workspace_id", "actor_id", "created_at", "id"}
}

func auditEventRecordCursorColumns() []string {
	return []string{"workspace_id", "object_key", "record_id", "created_at", "id"}
}

func ensureMySQLAuditCursorColumns(ctx context.Context, s Store) error {
	if s.Driver() != "mysql" {
		return nil
	}
	type columnSpec struct {
		name        string
		nullability string
	}
	specs := []columnSpec{{name: "id", nullability: "NOT NULL"}, {name: "created_at", nullability: "NOT NULL"}}
	query := "SELECT COLUMN_NAME, COLUMN_TYPE, CHARACTER_SET_NAME, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + s.Placeholder(1) + " AND COLUMN_NAME IN (" + s.Placeholder(2) + ", " + s.Placeholder(3) + ")"
	rows, err := s.SchemaDB().QueryContext(ctx, query, "_audit_events", specs[0].name, specs[1].name)
	if err != nil {
		return fmt.Errorf("inspect MySQL audit cursor columns: %w", err)
	}
	type columnState struct{ columnType, characterSet, collation string }
	states := map[string]columnState{}
	for rows.Next() {
		var name string
		var state columnState
		if err := rows.Scan(&name, &state.columnType, &state.characterSet, &state.collation); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan MySQL audit cursor column: %w", err)
		}
		states[name] = state
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate MySQL audit cursor columns: %w", err)
	}
	_ = rows.Close()
	modifications := make([]string, 0, len(specs))
	for _, spec := range specs {
		state, exists := states[spec.name]
		if !exists {
			return fmt.Errorf("inspect MySQL audit cursor columns: %s is missing", spec.name)
		}
		if strings.EqualFold(state.columnType, "varchar(191)") && strings.EqualFold(state.characterSet, "ascii") && strings.EqualFold(state.collation, "ascii_bin") {
			continue
		}
		modifications = append(modifications, "MODIFY COLUMN "+s.Identifier(spec.name)+" "+mysqlAuditCursorColumnType+" "+spec.nullability)
	}
	if len(modifications) == 0 {
		return nil
	}
	if _, err := s.SchemaDB().ExecContext(ctx, "ALTER TABLE "+s.TableIdentifier("_audit_events")+" "+strings.Join(modifications, ", ")); err != nil {
		return fmt.Errorf("normalize MySQL audit cursor columns: %w", err)
	}
	return nil
}
