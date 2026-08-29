// Audit persistence.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

type AuditStore struct {
	store *database.IdentityStore
	db    *sql.DB
}

func NewAuditStore(store *database.IdentityStore) AuditStore {
	return AuditStore{store: store, db: store.DB()}
}

func (r AuditStore) executor(ctx context.Context) database.ActionExecutionExecutor {
	if transaction := database.ActionExecutionTransaction(ctx); transaction != nil {
		return transaction
	}
	return r.db
}

func (r AuditStore) InsertAuditEvent(ctx context.Context, workspaceID string, event auditmodel.AuditEvent) error {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	workspaceID = workspace.String()
	if strings.TrimSpace(event.WorkspaceID) != workspaceID {
		return fmt.Errorf("audit event workspace %q does not match repository workspace %q", event.WorkspaceID, workspaceID)
	}
	beforeJSON, err := json.Marshal(event.Before)
	if err != nil {
		return fmt.Errorf("encode audit before: %w", err)
	}
	afterJSON, err := json.Marshal(event.After)
	if err != nil {
		return fmt.Errorf("encode audit after: %w", err)
	}
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	query, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(r.store.BuilderRenderer(), "_audit_events", workspaceID).
		Columns("id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at").
		Values(event.ID, event.Event, event.ObjectKey, event.RecordID, event.ActorID, event.RoleKey, event.Summary, string(metadataJSON), string(beforeJSON), string(afterJSON), event.CreatedAt).Build()
	if buildErr != nil {
		return fmt.Errorf("build audit event insert: %w", buildErr)
	}
	_, err = r.executor(ctx).ExecContext(ctx, query, arguments...)
	if err != nil {
		// A deterministic idempotent event may race or be replayed after the
		// business mutation committed. Only the exact previously stored payload
		// is accepted; the same key with different facts remains a hard error.
		var storedEvent, objectKey, recordID, actorID, roleKey, summary, storedMetadata, storedBefore, storedAfter string
		lookup, lookupArguments, lookupBuildErr := ormbuilder.NewWorkspaceSelectBuilder(r.store.BuilderRenderer(), "_audit_events", workspaceID).
			Columns("event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json").
			Where(ormbuilder.Equal("id", event.ID)).Build()
		if lookupBuildErr != nil {
			return fmt.Errorf("build audit event replay read: %w", lookupBuildErr)
		}
		lookupErr := r.executor(ctx).QueryRowContext(ctx, lookup, lookupArguments...).Scan(&storedEvent, &objectKey, &recordID, &actorID, &roleKey, &summary, &storedMetadata, &storedBefore, &storedAfter)
		if lookupErr == nil && storedEvent == event.Event && objectKey == event.ObjectKey && recordID == event.RecordID && actorID == event.ActorID && roleKey == event.RoleKey && summary == event.Summary && storedMetadata == string(metadataJSON) && storedBefore == string(beforeJSON) && storedAfter == string(afterJSON) {
			return nil
		}
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func escapeSQLLike(value string) string {
	value = strings.ReplaceAll(value, "~", "~~")
	value = strings.ReplaceAll(value, "%", "~%")
	return strings.ReplaceAll(value, "_", "~_")
}

func auditEventClassExpression() ormbuilder.Expression {
	return ormbuilder.Lower(ormbuilder.Concat(
		ormbuilder.Coalesce(ormbuilder.Column("event"), ormbuilder.Value("")),
		ormbuilder.Value(" "),
		ormbuilder.Coalesce(ormbuilder.Column("object_key"), ormbuilder.Value("")),
	))
}

func (r AuditStore) ListAuditEvents(ctx context.Context, workspaceID string, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	return r.listAuditEvents(ctx, workspace.String(), true, query)
}

func (r AuditStore) ListAuditEventsForSystem(ctx context.Context, scope identitymodel.SystemScope, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	if _, err := identitymodel.NewSystemQueryScope(scope); err != nil {
		return nil, err
	}
	return r.listAuditEvents(ctx, "", false, query)
}

func (r AuditStore) listAuditEvents(ctx context.Context, workspaceID string, scoped bool, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	predicates := []ormbuilder.Predicate{}
	addEqual := func(column, value string) {
		if value = strings.TrimSpace(value); value != "" {
			predicates = append(predicates, ormbuilder.Equal(column, value))
		}
	}
	addEqual("object_key", query.ObjectKey)
	addEqual("record_id", query.RecordID)
	addEqual("event", query.Event)
	addEqual("actor_id", query.ActorID)
	addEqual("role_key", query.RoleKey)
	eventClassValue := auditEventClassExpression()
	switch strings.TrimSpace(query.Class) {
	case auditmodel.AuditEventClassOperations:
		predicates = append(predicates, auditClassMarkerPredicate(eventClassValue, auditmodel.AuditEventClassMarkers(auditmodel.AuditEventClassOperations)))
	case auditmodel.AuditEventClassGovernance:
		operations := auditClassMarkerPredicate(eventClassValue, auditmodel.AuditEventClassMarkers(auditmodel.AuditEventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, auditmodel.AuditEventClassMarkers(auditmodel.AuditEventClassGovernance))
		predicates = append(predicates, ormbuilder.And(ormbuilder.Not(operations), governance))
	case auditmodel.AuditEventClassBusiness:
		operations := auditClassMarkerPredicate(eventClassValue, auditmodel.AuditEventClassMarkers(auditmodel.AuditEventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, auditmodel.AuditEventClassMarkers(auditmodel.AuditEventClassGovernance))
		predicates = append(predicates, ormbuilder.And(ormbuilder.Not(operations), ormbuilder.Not(governance)))
	}
	if value := strings.TrimSpace(query.CreatedFrom); value != "" {
		predicates = append(predicates, ormbuilder.GreaterThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.CreatedTo); value != "" {
		predicates = append(predicates, ormbuilder.LessThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.RequestID); value != "" {
		encodedRequestID, _ := json.Marshal(value)
		predicates = append(predicates, ormbuilder.LikeEscaped("metadata_json", "%"+escapeSQLLike(`"request_id":`+string(encodedRequestID))+"%"))
	}
	if value := strings.TrimSpace(query.Cursor); value != "" {
		cursor, err := auditmodel.DecodeAuditEventCursor(value)
		if err != nil {
			return nil, fmt.Errorf("decode audit event cursor: %w", err)
		}
		predicates = append(predicates, ormbuilder.Or(
			ormbuilder.LessThan("created_at", cursor.CreatedAt),
			ormbuilder.And(ormbuilder.Equal("created_at", cursor.CreatedAt), ormbuilder.LessThan("id", cursor.ID)),
		))
	}
	columns := []string{"id", "workspace_id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at"}
	var selectBuilder *ormbuilder.SelectBuilder
	if scoped {
		selectBuilder = ormbuilder.NewWorkspaceSelectBuilder(r.store.BuilderRenderer(), "_audit_events", workspaceID)
	} else {
		selectBuilder = ormbuilder.NewSelectBuilder(r.store.BuilderRenderer(), "_audit_events")
	}
	selectBuilder.Columns(columns...).OrderBy(ormbuilder.Descending("created_at"), ormbuilder.Descending("id")).Limit(limit)
	if len(predicates) > 0 {
		selectBuilder.Where(ormbuilder.And(predicates...))
	}
	statement, arguments, err := selectBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("build audit event list: %w", err)
	}
	rows, err := r.executor(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	events := []auditmodel.AuditEvent{}
	for rows.Next() {
		var event auditmodel.AuditEvent
		var metadataJSON, beforeJSON, afterJSON string
		if err := rows.Scan(&event.ID, &event.WorkspaceID, &event.Event, &event.ObjectKey, &event.RecordID, &event.ActorID, &event.RoleKey, &event.Summary, &metadataJSON, &beforeJSON, &afterJSON, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		_ = json.Unmarshal([]byte(metadataJSON), &event.Metadata)
		_ = json.Unmarshal([]byte(beforeJSON), &event.Before)
		_ = json.Unmarshal([]byte(afterJSON), &event.After)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit events: %w", err)
	}
	return events, nil
}

func auditClassMarkerPredicate(eventClassValue ormbuilder.Expression, markers []string) ormbuilder.Predicate {
	parts := make([]ormbuilder.Predicate, 0, len(markers))
	for _, marker := range markers {
		parts = append(parts, ormbuilder.LikeValueEscaped(eventClassValue, "%"+escapeSQLLike(strings.ToLower(marker))+"%"))
	}
	if len(parts) == 0 {
		return ormbuilder.Equal("id", nil)
	}
	return ormbuilder.Or(parts...)
}

func (r AuditStore) ListAuditOptions(ctx context.Context, workspaceID string, query auditmodel.AuditOptionQuery) ([]auditmodel.AuditOption, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	workspaceID = workspace.String()
	field := strings.TrimSpace(query.Field)
	switch field {
	case "record_id", "actor_id", "role_key", "event":
	default:
		return nil, fmt.Errorf("unsupported audit option field %q", field)
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 10
	} else if limit > 50 {
		limit = 50
	}
	predicates := []ormbuilder.Predicate{ormbuilder.NotEqual(field, "")}
	for _, filter := range []struct{ column, value, operator string }{{"object_key", query.ObjectKey, " = "}, {"created_at", query.CreatedFrom, " >= "}, {"created_at", query.CreatedTo, " <= "}} {
		if value := strings.TrimSpace(filter.value); value != "" {
			switch filter.operator {
			case " >= ":
				predicates = append(predicates, ormbuilder.GreaterThanOrEqual(filter.column, value))
			case " <= ":
				predicates = append(predicates, ormbuilder.LessThanOrEqual(filter.column, value))
			default:
				predicates = append(predicates, ormbuilder.Equal(filter.column, value))
			}
		}
	}
	if value := strings.TrimSpace(query.Query); value != "" {
		predicates = append(predicates, ormbuilder.LikeEscaped(field, "%"+escapeSQLLike(value)+"%"))
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(r.store.BuilderRenderer(), "_audit_events", workspaceID).
		Projections(ormbuilder.Project(ormbuilder.Column(field)), ormbuilder.Project(ormbuilder.CountAll())).
		Where(ormbuilder.And(predicates...)).GroupBy(ormbuilder.Column(field)).
		OrderBy(ormbuilder.DescendingExpression(ormbuilder.CountAll()), ormbuilder.Ascending(field)).Limit(limit).Build()
	if err != nil {
		return nil, fmt.Errorf("build audit option list: %w", err)
	}
	rows, err := r.executor(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list audit options: %w", err)
	}
	defer rows.Close()
	options := []auditmodel.AuditOption{}
	for rows.Next() {
		var option auditmodel.AuditOption
		if err := rows.Scan(&option.Value, &option.Count); err != nil {
			return nil, fmt.Errorf("scan audit option: %w", err)
		}
		option.Label = option.Value
		options = append(options, option)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit options: %w", err)
	}
	return options, nil
}
