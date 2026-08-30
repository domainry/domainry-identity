package metadata

import auditmodel "github.com/domainry/domainry-audit-sdk/contract"

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	"sort"
	"strconv"
	"strings"
	"time"

	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s MetadataStore) UpsertMetadataDefinition(ctx context.Context, resourceType string, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest) (metadatamodel.MetadataDefinition, error) {
	resourceType = strings.TrimSpace(resourceType)
	resourceKey = strings.TrimSpace(resourceKey)
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if len(req.Payload) == 0 {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata payload is required")
	}
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, req)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	raw, hash, _ := metadataPayload(shape.Payload)
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "legacy metadata definition upsert")
	if replay, found, replayErr := s.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr != nil {
		return metadatamodel.MetadataDefinition{}, replayErr
	} else if found {
		return replay, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	sourceKind := strings.TrimSpace(req.SourceKind)
	if sourceKind == "" {
		sourceKind = "user"
	}
	sourceID := strings.TrimSpace(req.SourceID)
	if sourceID == "" {
		sourceID = "metadata_api"
	}
	schemaVersion, err := s.nextMetadataSchemaVersion(ctx, resourceType, shape.Key)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("begin metadata upsert: %w", err)
	}
	defer tx.Rollback()
	if err := s.replaceMetadataDefinitionVersion(ctx, tx, table, resourceType, shape.Key, req.ExpectedSchemaHash); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	values := []any{
		metadataResourceID(resourceType, shape.Key),
		shape.Key,
		shape.ObjectKey,
		shape.Name,
		string(raw),
		schemaVersion,
		hash,
		sourceKind,
		sourceID,
		nil,
		now,
		now,
	}
	statement, arguments, err := ormbuilder.NewInsertBuilder(s.store.SQLRenderer, table).
		Columns("id", "resource_key", "object_key", "name", "payload_json", "schema_version", "schema_hash", "source_kind", "source_id", "disabled_at", "created_at", "updated_at").Values(values...).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("build %s %s insert: %w", resourceType, shape.Key, err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		_ = tx.Rollback()
		if replay, found, replayErr := s.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr == nil && found {
			return replay, nil
		}
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("insert %s %s: %w", resourceType, shape.Key, err)
	}
	versionValues := []any{
		metadataResourceID(resourceType+":version", shape.Key+":"+schemaVersion+":"+metadataHashPrefix(hash)),
		resourceType,
		shape.Key,
		schemaVersion,
		hash,
		string(raw),
		now,
	}
	statement, arguments, err = metadataVersionInsert(s, versionValues...).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("build %s %s version insert: %w", resourceType, shape.Key, err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		_ = tx.Rollback()
		if replay, found, replayErr := s.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr == nil && found {
			return replay, nil
		}
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("insert %s %s version: %w", resourceType, shape.Key, err)
	}
	if err := tx.Commit(); err != nil {
		if replay, found, replayErr := s.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr == nil && found {
			return replay, nil
		}
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("commit metadata upsert: %w", err)
	}
	// Refresh catalog schema_hash so /schema ETag changes on the next request.
	return metadatamodel.MetadataDefinition{
		ResourceType:  resourceType,
		ResourceKey:   shape.Key,
		ObjectKey:     shape.ObjectKey,
		Name:          shape.Name,
		Payload:       append([]byte(nil), raw...),
		SchemaVersion: schemaVersion,
		SchemaHash:    hash,
		SourceKind:    sourceKind,
		SourceID:      sourceID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

func (s MetadataStore) replaceMetadataDefinitionVersion(ctx context.Context, tx *sql.Tx, table, resourceType, resourceKey string, expectedHash *string) error {
	if expectedHash == nil {
		statement, arguments, err := ormbuilder.NewDeleteBuilder(s.store.SQLRenderer, table).Where(ormbuilder.Equal("resource_key", resourceKey)).Build()
		if err != nil {
			return fmt.Errorf("build replace %s %s delete: %w", resourceType, resourceKey, err)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return fmt.Errorf("replace %s %s: %w", resourceType, resourceKey, err)
		}
		return nil
	}
	expected := strings.TrimSpace(*expectedHash)
	if expected == "" {
		var current string
		statement, arguments, buildErr := metadataHashSelect(s, table, resourceKey).Build()
		if buildErr != nil {
			return fmt.Errorf("build current %s %s version query: %w", resourceType, resourceKey, buildErr)
		}
		err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&current)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read current %s %s version: %w", resourceType, resourceKey, err)
		}
		return &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current}
	}
	statement, arguments, err := ormbuilder.NewDeleteBuilder(s.store.SQLRenderer, table).
		Where(ormbuilder.And(ormbuilder.Equal("resource_key", resourceKey), ormbuilder.Equal("schema_hash", expected))).Build()
	if err != nil {
		return fmt.Errorf("build replace %s %s delete: %w", resourceType, resourceKey, err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return fmt.Errorf("replace %s %s: %w", resourceType, resourceKey, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("read replaced %s %s rows: %w", resourceType, resourceKey, rowsErr)
	}
	if affected == 1 {
		return nil
	}
	var current string
	statement, arguments, buildErr := metadataHashSelect(s, table, resourceKey).Build()
	if buildErr != nil {
		return fmt.Errorf("build conflicting %s %s version query: %w", resourceType, resourceKey, buildErr)
	}
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&current); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read conflicting %s %s version: %w", resourceType, resourceKey, err)
	}
	return &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current}
}

func (s MetadataStore) nextMetadataSchemaVersion(ctx context.Context, resourceType string, resourceKey string) (string, error) {
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, "metadata_definition_versions").
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.And(ormbuilder.Equal("resource_type", resourceType), ormbuilder.Equal("resource_key", resourceKey))).Build()
	if err != nil {
		return "", fmt.Errorf("build metadata version count query: %w", err)
	}
	var count int
	if err := s.database().QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
		return "", fmt.Errorf("read metadata version count: %w", err)
	}
	return fmt.Sprintf("%d", count+1), nil
}

func metadataHashSelect(s MetadataStore, table, resourceKey string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_hash").Where(ormbuilder.Equal("resource_key", resourceKey))
}

// DisableMetadataDefinition soft-deletes a definition by setting disabled_at; no physical DROP is performed.
func (s MetadataStore) DisableMetadataDefinition(ctx context.Context, resourceType string, resourceKey string) error {
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	statement, arguments, err := ormbuilder.NewUpdateBuilder(s.store.SQLRenderer, table).Set("disabled_at", now).Where(ormbuilder.Equal("resource_key", resourceKey)).Build()
	if err != nil {
		return fmt.Errorf("build disable %s %s update: %w", resourceType, resourceKey, err)
	}
	result, err := s.database().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return fmt.Errorf("disable %s %s: %w", resourceType, resourceKey, err)
	}
	rows, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("read disabled %s %s rows: %w", resourceType, resourceKey, rowsErr)
	}
	if rows == 0 {
		return fmt.Errorf("metadata.%s.notFound: %s", resourceType, resourceKey)
	}
	return nil
}

// ListMetadataDefinitions returns all active (non-disabled) definitions for the given resourceType.
// If workspaceID is non-empty, only definitions matching that workspace are returned (P2-4 isolation).
func (s MetadataStore) ListMetadataDefinitions(ctx context.Context, resourceType string, workspaceID string) ([]metadatamodel.MetadataDefinition, error) {
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return nil, err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	builder := metadataDefinitionSelect(s, table).Where(ormbuilder.IsNull("disabled_at"))
	if workspaceID != "" {
		builder.Where(ormbuilder.And(ormbuilder.IsNull("disabled_at"), ormbuilder.Equal("source_id", workspaceID)))
	}
	statement, arguments, err := builder.OrderBy(ormbuilder.Ascending("resource_key")).Build()
	if err != nil {
		return nil, fmt.Errorf("build %s definitions query: %w", resourceType, err)
	}
	rows, err := s.database().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list %s definitions: %w", resourceType, err)
	}
	defer rows.Close()
	var out []metadatamodel.MetadataDefinition
	for rows.Next() {
		var d metadatamodel.MetadataDefinition
		var payloadJSON string
		var disabledAt sql.NullString
		if err := rows.Scan(&d.ResourceKey, &d.ObjectKey, &d.Name, &payloadJSON, &d.SchemaVersion, &d.SchemaHash, &d.SourceKind, &d.SourceID, &disabledAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan %s definition: %w", resourceType, err)
		}
		d.ResourceType = resourceType
		d.Payload = json.RawMessage(payloadJSON)
		if disabledAt.Valid {
			d.DisabledAt = disabledAt.String
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetMetadataDefinition returns a single definition by type and key.
func (s MetadataStore) GetMetadataDefinition(ctx context.Context, resourceType string, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	statement, arguments, err := metadataDefinitionSelect(s, table).Where(ormbuilder.Equal("resource_key", resourceKey)).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, fmt.Errorf("build %s definition query: %w", resourceType, err)
	}
	var d metadatamodel.MetadataDefinition
	var payloadJSON string
	var disabledAt sql.NullString
	err = s.database().QueryRowContext(ctx, statement, arguments...).Scan(&d.ResourceKey, &d.ObjectKey, &d.Name, &payloadJSON, &d.SchemaVersion, &d.SchemaHash, &d.SourceKind, &d.SourceID, &disabledAt, &d.CreatedAt, &d.UpdatedAt)
	if err == sql.ErrNoRows {
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, fmt.Errorf("get %s definition: %w", resourceType, err)
	}
	d.ResourceType = resourceType
	d.Payload = json.RawMessage(payloadJSON)
	if disabledAt.Valid {
		d.DisabledAt = disabledAt.String
	}
	return d, true, nil
}

// ListMetadataDefinitionVersions returns the version history for a definition.
func (s MetadataStore) ListMetadataDefinitionVersions(ctx context.Context, resourceType string, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, "metadata_definition_versions").Columns("schema_version", "schema_hash", "payload_json", "created_at").
		Where(ormbuilder.And(ormbuilder.Equal("resource_type", resourceType), ormbuilder.Equal("resource_key", resourceKey))).OrderBy(ormbuilder.Descending("created_at")).Build()
	if err != nil {
		return nil, fmt.Errorf("build versions %s %s query: %w", resourceType, resourceKey, err)
	}
	rows, err := s.database().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list versions %s %s: %w", resourceType, resourceKey, err)
	}
	defer rows.Close()
	var out []metadatamodel.MetadataDefinitionVersion
	for rows.Next() {
		var v metadatamodel.MetadataDefinitionVersion
		var payloadJSON string
		if err := rows.Scan(&v.SchemaVersion, &v.SchemaHash, &payloadJSON, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		v.ResourceType = resourceType
		v.ResourceKey = resourceKey
		v.Payload = json.RawMessage(payloadJSON)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, leftErr := strconv.Atoi(strings.TrimSpace(out[i].SchemaVersion))
		right, rightErr := strconv.Atoi(strings.TrimSpace(out[j].SchemaVersion))
		if leftErr == nil && rightErr == nil && left != right {
			return left > right
		}
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].SchemaVersion > out[j].SchemaVersion
	})
	return out, nil
}

// RollbackMetadataDefinition restores a definition to a specific schema_version from its version history.
func (s MetadataStore) RollbackMetadataDefinition(ctx context.Context, resourceType string, resourceKey string, request metadatamodel.MetadataDefinitionRollbackRequest, audit auditmodel.AuditEvent) (metadatamodel.MetadataDefinition, error) {
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("begin rollback: %w", err)
	}
	defer tx.Rollback()
	statement, arguments, err := ormbuilder.NewSelectBuilder(s.store.SQLRenderer, "metadata_definition_versions").Columns("payload_json", "schema_hash").
		Where(ormbuilder.And(ormbuilder.Equal("resource_type", resourceType), ormbuilder.Equal("resource_key", resourceKey), ormbuilder.Equal("schema_version", request.TargetVersion))).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("build rollback version query: %w", err)
	}
	var payloadJSON, targetHash string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&payloadJSON, &targetHash); err == sql.ErrNoRows {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata.version.notFound: %s@%s", resourceKey, request.TargetVersion)
	} else if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback read version: %w", err)
	}
	nextVersion, err := s.nextMetadataSchemaVersionTx(ctx, tx, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, metadatamodel.MetadataDefinitionUpsertRequest{Payload: json.RawMessage(payloadJSON)})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback decode target: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	statement, arguments, err = ormbuilder.NewUpdateBuilder(s.store.SQLRenderer, table).
		Set("payload_json", payloadJSON).Set("object_key", shape.ObjectKey).Set("name", shape.Name).Set("schema_version", nextVersion).
		Set("schema_hash", targetHash).Set("source_kind", "builder").Set("source_id", request.ChangePlanID).Set("disabled_at", nil).Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("resource_key", resourceKey), ormbuilder.Equal("schema_hash", request.ExpectedSchemaHash))).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("build rollback update: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback update: %w", err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("read rollback update rows: %w", rowsErr)
	}
	if affected != 1 {
		return metadatamodel.MetadataDefinition{}, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: request.ExpectedSchemaHash, CurrentHash: s.currentMetadataHashTx(ctx, tx, table, resourceKey)}
	}
	if err := s.insertMetadataDefinitionVersionTx(ctx, tx, resourceType, resourceKey, nextVersion, targetHash, []byte(payloadJSON), now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := s.syncMetadataLocalizedTextTx(ctx, tx, resourceType, resourceKey, []byte(payloadJSON), request.ChangePlanID, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := s.insertMetadataChangeAudit(ctx, tx, audit); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := s.stageMetadataRollbackIntentTx(ctx, tx, resourceType, resourceKey, request, audit, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := tx.Commit(); err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("commit rollback: %w", err)
	}
	d, _, err := s.GetMetadataDefinition(ctx, resourceType, resourceKey)
	return d, err
}

func (s MetadataStore) stageMetadataRollbackIntentTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string, request metadatamodel.MetadataDefinitionRollbackRequest, audit auditmodel.AuditEvent, now string) error {
	planID := strings.TrimSpace(request.ChangePlanID)
	if planID == "" {
		return fmt.Errorf("rollback change plan id is required")
	}
	workspaceID, err := identitymodel.NewWorkspaceID(audit.WorkspaceID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"operation": "metadata_rollback", "resource_type": resourceType, "resource_key": resourceKey, "target_version": request.TargetVersion, "expected_schema_hash": request.ExpectedSchemaHash, "business_reason": request.BusinessReason, "builder_task_id": request.BuilderTaskID})
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer, "identity_change_plan_drafts", workspaceID.String()).
		Set("status", "applying").Set("payload_json", string(payload)).Set("updated_by", audit.ActorID).Set("updated_at", now).
		SetExpression("revision", ormbuilder.Add(ormbuilder.Column("revision"), ormbuilder.Value(1))).
		Where(ormbuilder.And(ormbuilder.Equal("plan_id", planID), ormbuilder.Equal("status", "draft"))).Build()
	if err != nil {
		return fmt.Errorf("build rollback change plan stage: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return fmt.Errorf("stage rollback change plan: %w", err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("read staged rollback change plan rows: %w", rowsErr)
	}
	if affected == 1 {
		return nil
	}
	statement, arguments, err = ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer, "identity_change_plan_drafts", workspaceID.String()).
		Columns("plan_id", "revision", "status", "payload_json", "created_by", "updated_by", "created_at", "updated_at").
		Values(planID, 1, "applying", string(payload), audit.ActorID, audit.ActorID, now, now).Build()
	if err != nil {
		return fmt.Errorf("build rollback change plan intent insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create rollback change plan intent: %w", err)
	}
	return nil
}
