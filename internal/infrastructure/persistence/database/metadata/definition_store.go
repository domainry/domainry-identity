package metadata

import auditmodel "github.com/domainry/domainry-audit-sdk/contract"

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/domainry/domainry-orm/query"
)

func (s MetadataStore) UpsertMetadataDefinition(ctx context.Context, resourceType string, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest) (metadatamodel.MetadataDefinition, error) {
	resourceType = strings.TrimSpace(resourceType)
	resourceKey = strings.TrimSpace(resourceKey)
	moduleOwned := metadataModuleOwnsDefinition(resourceType)
	if moduleOwned {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definitions are read-only from Identity", resourceType)
	}
	table := ""
	var tableErr error
	table, tableErr = metadataDefinitionTable(resourceType)
	if tableErr != nil {
		return metadatamodel.MetadataDefinition{}, tableErr
	}
	if len(req.Payload) == 0 {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata payload is required")
	}
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, req)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	raw, hash, _ := metadataPayload(shape.Payload)
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "metadata definition upsert")
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
	definition := metadatamodel.MetadataDefinition{ResourceType: resourceType, ResourceKey: shape.Key, ObjectKey: shape.ObjectKey, Name: shape.Name, Payload: append([]byte(nil), raw...), SchemaVersion: schemaVersion, SchemaHash: hash, SourceKind: sourceKind, SourceID: sourceID, CreatedAt: now, UpdatedAt: now}
	if err := s.replaceMetadataDefinitionVersion(ctx, tx, table, resourceType, shape.Key, req.ExpectedSchemaHash); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	values := []any{metadataResourceID(resourceType, shape.Key), shape.Key, shape.ObjectKey, shape.Name, string(raw), schemaVersion, hash, sourceKind, sourceID, nil, now, now}
	statement, arguments, err := query.NewInsertBuilder(s.store.SQLRenderer, table).
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
	if err := s.insertOwnedDefinitionVersion(ctx, tx, metadataDefinitionVersion{
		ResourceType: resourceType, ResourceKey: shape.Key, SchemaVersion: schemaVersion,
		SchemaHash: hash, Payload: raw, CreatedAt: now,
	}); err != nil {
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

	return definition, nil
}

func (s MetadataStore) replaceMetadataDefinitionVersion(ctx context.Context, tx *sql.Tx, table, resourceType, resourceKey string, expectedHash *string) error {
	if expectedHash == nil {
		statement, arguments, err := query.NewDeleteBuilder(s.store.SQLRenderer, table).Where(query.Equal("resource_key", resourceKey)).Build()
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
	statement, arguments, err := query.NewDeleteBuilder(s.store.SQLRenderer, table).
		Where(query.And(query.Equal("resource_key", resourceKey), query.Equal("schema_hash", expected))).Build()
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
	count, err := s.countOwnedDefinitionVersions(ctx, s.database(), resourceType, resourceKey)
	if err != nil {
		return "", fmt.Errorf("read metadata version count: %w", err)
	}
	return fmt.Sprintf("%d", count+1), nil
}

func metadataHashSelect(s MetadataStore, table, resourceKey string) *query.SelectBuilder {
	return query.NewSelectBuilder(s.store.SQLRenderer, table).Columns("schema_hash").Where(query.Equal("resource_key", resourceKey))
}

func (s MetadataStore) DisableMetadataDefinition(ctx context.Context, resourceType string, resourceKey string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if metadataModuleOwnsDefinition(resourceType) {
		return fmt.Errorf("Metadata-owned %s definitions are read-only from Identity", resourceType)
	}
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return err
	}
	statement, arguments, err := query.NewUpdateBuilder(s.store.SQLRenderer, table).Set("disabled_at", now).Where(query.Equal("resource_key", resourceKey)).Build()
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

func (s MetadataStore) ListMetadataDefinitions(ctx context.Context, resourceType string, workspaceID string) ([]metadatamodel.MetadataDefinition, error) {
	if metadataModuleOwnsDefinition(resourceType) {
		definitions, err := s.metadataModuleDefinitions()
		if err != nil {
			return nil, err
		}
		values, err := definitions.List(ctx, metadatasdk.DefinitionQuery{Owner: metadatasdk.DefinitionOwnerMetadata, ResourceType: resourceType, SourceID: workspaceID})
		if err != nil {
			return nil, fmt.Errorf("list %s definitions: %w", resourceType, err)
		}
		out := make([]metadatamodel.MetadataDefinition, len(values))
		for index, value := range values {
			out[index] = metadataDefinitionFromModule(value)
		}
		return out, nil
	}
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return nil, err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	builder := metadataDefinitionSelect(s, table).Where(query.IsNull("disabled_at"))
	if workspaceID != "" {
		builder.Where(query.And(query.IsNull("disabled_at"), query.Equal("source_id", workspaceID)))
	}
	statement, arguments, err := builder.OrderBy(query.Ascending("resource_key")).Build()
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

func (s MetadataStore) GetMetadataDefinition(ctx context.Context, resourceType string, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	if metadataModuleOwnsDefinition(resourceType) {
		definitions, err := s.metadataModuleDefinitions()
		if err != nil {
			return metadatamodel.MetadataDefinition{}, false, err
		}
		value, found, err := definitions.Get(ctx, metadatasdk.DefinitionOwnerMetadata, resourceType, resourceKey)
		if err != nil {
			return metadatamodel.MetadataDefinition{}, false, fmt.Errorf("get %s definition: %w", resourceType, err)
		}
		if !found {
			return metadatamodel.MetadataDefinition{}, false, nil
		}
		return metadataDefinitionFromModule(value), true, nil
	}
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	statement, arguments, err := metadataDefinitionSelect(s, table).Where(query.Equal("resource_key", resourceKey)).Build()
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

func (s MetadataStore) ListMetadataDefinitionVersions(ctx context.Context, resourceType string, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	values, err := s.listOwnedDefinitionVersions(ctx, s.database(), resourceType, resourceKey)
	if err != nil {
		return nil, fmt.Errorf("list versions %s %s: %w", resourceType, resourceKey, err)
	}
	out := make([]metadatamodel.MetadataDefinitionVersion, len(values))
	for index, value := range values {
		out[index] = metadatamodel.MetadataDefinitionVersion{ResourceType: value.ResourceType, ResourceKey: value.ResourceKey, SchemaVersion: value.SchemaVersion, SchemaHash: value.SchemaHash, Payload: append([]byte(nil), value.Payload...), CreatedAt: value.CreatedAt}
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

func (s MetadataStore) RollbackMetadataDefinition(ctx context.Context, resourceType string, resourceKey string, request metadatamodel.MetadataDefinitionRollbackRequest, audit auditmodel.AuditEvent) (metadatamodel.MetadataDefinition, error) {
	moduleOwned := metadataModuleOwnsDefinition(resourceType)
	if moduleOwned {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definition rollback is unavailable from Identity", resourceType)
	}
	table := ""
	var tableErr error
	table, tableErr = metadataDefinitionTable(resourceType)
	if tableErr != nil {
		return metadatamodel.MetadataDefinition{}, tableErr
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("begin rollback: %w", err)
	}
	defer tx.Rollback()
	version, found, err := s.getOwnedDefinitionVersion(ctx, tx, resourceType, resourceKey, request.TargetVersion)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback read version: %w", err)
	}
	if !found {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata.version.notFound: %s@%s", resourceKey, request.TargetVersion)
	}
	payloadJSON, targetHash := string(version.Payload), version.SchemaHash
	var statement string
	var arguments []any
	nextVersion, err := s.nextMetadataSchemaVersionTx(ctx, tx, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, metadatamodel.MetadataDefinitionUpsertRequest{Payload: json.RawMessage(payloadJSON)})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback decode target: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	statement, arguments, err = query.NewUpdateBuilder(s.store.SQLRenderer, table).
		Set("payload_json", payloadJSON).Set("object_key", shape.ObjectKey).Set("name", shape.Name).Set("schema_version", nextVersion).
		Set("schema_hash", targetHash).Set("source_kind", "rollback").Set("source_id", request.SourceID).Set("disabled_at", nil).Set("updated_at", now).
		Where(query.And(query.Equal("resource_key", resourceKey), query.Equal("schema_hash", request.ExpectedSchemaHash))).Build()
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
	if err := s.syncMetadataLocalizedTextTx(ctx, tx, resourceType, resourceKey, []byte(payloadJSON), request.SourceID, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := s.insertMetadataChangeAudit(ctx, tx, audit); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := tx.Commit(); err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("commit rollback: %w", err)
	}
	d, _, err := s.GetMetadataDefinition(ctx, resourceType, resourceKey)
	return d, err
}
