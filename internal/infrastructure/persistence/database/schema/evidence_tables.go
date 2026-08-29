package schema

import (
	"context"
	"fmt"

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
