package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type lifecycleSQLStore interface {
	DB() *sql.DB
	BuilderRenderer() ormdialect.Renderer
}

type AuditSubjectLifecycleStore struct{ store lifecycleSQLStore }

func NewAuditSubjectLifecycleStore(store lifecycleSQLStore) *AuditSubjectLifecycleStore {
	return &AuditSubjectLifecycleStore{store: store}
}

func (s *AuditSubjectLifecycleStore) Owner(context.Context) string { return "audit" }

func (s *AuditSubjectLifecycleStore) PreviewSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	var count int64
	query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.BuilderRenderer(), "_audit_events", workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	if err := s.store.DB().QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]int64{"audit_references": count})
}

func (s *AuditSubjectLifecycleStore) ExportSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	projections := []ormbuilder.Projection{}
	for _, column := range []string{"id", "event", "object_key", "record_id", "summary", "created_at"} {
		projections = append(projections, ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.Column(column), ormbuilder.Value(""))))
	}
	query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.BuilderRenderer(), "_audit_events", workspaceID).
		Projections(projections...).Where(ormbuilder.Equal("actor_id", identity)).OrderBy(ormbuilder.Ascending("created_at")).Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.store.DB().QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var id, event, objectKey, recordID, summary, createdAt string
		if err := rows.Scan(&id, &event, &objectKey, &recordID, &summary, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]string{"id": id, "event": event, "object_key": objectKey, "record_id": recordID, "summary": summary, "created_at": createdAt})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

func (s *AuditSubjectLifecycleStore) EraseSubject(ctx context.Context, workspaceID, identity string, _ []privacy.LegalHold) (json.RawMessage, error) {
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + identity))
	anonymous := "erased-" + hex.EncodeToString(sum[:12])
	query, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.BuilderRenderer(), "_audit_events", workspaceID).
		Set("actor_id", anonymous).Where(ormbuilder.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	result, err := s.store.DB().ExecContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"anonymized_audit_references": changed, "event_integrity_preserved": true, "at": time.Now().UTC()})
}
