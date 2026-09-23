package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	shareddefinition "github.com/domainry/domainry-foundation/definition"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (r MetadataStore) PublishDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) (metadatamodel.MetadataDefinition, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	return r.publishDefinition(ctx, scope, resourceType, resourceKey, req, &audit, publication)
}

func (r MetadataStore) publishDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest, audit *auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) (metadatamodel.MetadataDefinition, error) {
	resourceType, resourceKey = strings.TrimSpace(resourceType), strings.TrimSpace(resourceKey)
	moduleOwned := metadataModuleOwnsDefinition(resourceType)
	if moduleOwned {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definitions are read-only from Identity", resourceType)
	}
	if len(req.Payload) == 0 {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata payload is required")
	}
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, req)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	raw, hash, _ := metadataPayload(shape.Payload)
	if replay, found, replayErr := r.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr != nil {
		return metadatamodel.MetadataDefinition{}, replayErr
	} else if found {
		return replay, nil
	}
	sourceKind := metadataMutationValueOrDefault(req.SourceKind, "user")
	sourceID := metadataMutationValueOrDefault(req.SourceID, "metadata_api")
	tx, err := r.database().BeginTx(ctx, recordMutationTxOptions())
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("begin metadata upsert: %w", err)
	}
	defer tx.Rollback()
	definition, err := r.publishIdentityDefinition(ctx, tx, resourceType, shape.Key, shape, raw, hash, req, sourceKind, sourceID)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	now := definition.UpdatedAt
	if err := r.applyIdentityRoleProjectionMutation(ctx, tx, publication, metadatamodel.MetadataDefinitionMutation{Operation: "update", ResourceType: resourceType, ResourceKey: shape.Key, Request: req}, definition); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := r.syncLocalizedProjection(ctx, tx, resourceType, shape.Key, raw, sourceID, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if audit != nil {
		audit.After = metadataDefinitionAuditValue(definition)
		if audit.Metadata == nil {
			audit.Metadata = map[string]any{}
		}
		audit.Metadata["schema_version"], audit.Metadata["schema_hash"] = definition.SchemaVersion, definition.SchemaHash
		if err := r.insertChangeAudit(ctx, tx, *audit); err != nil {
			return metadatamodel.MetadataDefinition{}, err
		}
	}
	if err := r.refreshCatalogHashTx(ctx, tx, now); err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("refresh active metadata revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		if replay, found, replayErr := r.metadataDefinitionReplay(ctx, scope, resourceType, shape.Key, hash, req.ExpectedSchemaHash); replayErr == nil && found {
			return replay, nil
		}
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("commit metadata upsert: %w", err)
	}
	return definition, nil
}

func metadataDefinitionAuditValue(definition metadatamodel.MetadataDefinition) map[string]any {
	value := map[string]any{"resource_type": definition.ResourceType, "resource_key": definition.ResourceKey, "schema_version": definition.SchemaVersion, "schema_hash": definition.SchemaHash, "source_kind": definition.SourceKind, "source_id": definition.SourceID}
	var payload any
	if json.Unmarshal(definition.Payload, &payload) == nil {
		value["payload"] = payload
	}
	return value
}

func (r MetadataStore) DisableDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey, expectedSchemaHash string, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) error {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return err
	}
	tx, err := r.database().BeginTx(ctx, recordMutationTxOptions())
	if err != nil {
		return fmt.Errorf("begin disable %s %s: %w", resourceType, resourceKey, err)
	}
	defer tx.Rollback()
	expectedSchemaHash = strings.TrimSpace(expectedSchemaHash)
	mutation := metadatamodel.MetadataDefinitionMutation{
		Operation: "archive", ResourceType: strings.TrimSpace(resourceType), ResourceKey: strings.TrimSpace(resourceKey),
		Request: metadatamodel.MetadataDefinitionUpsertRequest{ExpectedSchemaHash: &expectedSchemaHash},
	}
	definition, err := r.applyDefinitionArchive(ctx, tx, mutation)
	if err != nil {
		return err
	}
	if err := r.applyIdentityRoleProjectionMutation(ctx, tx, publication, mutation, definition); err != nil {
		return err
	}
	if err := r.insertChangeAudit(ctx, tx, audit); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := r.refreshCatalogHashTx(ctx, tx, now); err != nil {
		return fmt.Errorf("refresh metadata catalog hash while disabling %s %s: %w", resourceType, resourceKey, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit disable %s %s: %w", resourceType, resourceKey, err)
	}
	return nil
}

func (r MetadataStore) ApplyDefinitionMutations(ctx context.Context, scope identitymodel.SystemScope, mutations []metadatamodel.MetadataDefinitionMutation, audits []auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) ([]metadatamodel.MetadataDefinition, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	tx, err := r.database().BeginTx(ctx, recordMutationTxOptions())
	if err != nil {
		return nil, fmt.Errorf("begin metadata publication: %w", err)
	}
	defer tx.Rollback()
	definitions := make([]metadatamodel.MetadataDefinition, 0, len(mutations))
	for _, mutation := range mutations {
		var definition metadatamodel.MetadataDefinition
		switch mutation.Operation {
		case "create", "update":
			definition, err = r.applyDefinitionUpsert(ctx, tx, mutation)
		case "archive", "delete":
			definition, err = r.applyDefinitionArchive(ctx, tx, mutation)
		case "noop":
			continue
		default:
			err = fmt.Errorf("metadata change operation is unsupported: %s", mutation.Operation)
		}
		if err != nil {
			return nil, err
		}
		if err := r.applyIdentityRoleProjectionMutation(ctx, tx, publication, mutation, definition); err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	for _, audit := range audits {
		if err := r.insertChangeAudit(ctx, tx, audit); err != nil {
			return nil, err
		}
	}
	if err := r.refreshCatalogHashTx(ctx, tx, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("refresh metadata catalog hash: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit metadata publication: %w", err)
	}
	return definitions, nil
}

func (r MetadataStore) applyDefinitionUpsert(ctx context.Context, tx *sql.Tx, mutation metadatamodel.MetadataDefinitionMutation) (metadatamodel.MetadataDefinition, error) {
	moduleOwned := metadataModuleOwnsDefinition(mutation.ResourceType)
	if moduleOwned {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definitions are read-only from Identity", mutation.ResourceType)
	}
	shape, err := metadataDefinitionShape(ctx, mutation.ResourceType, mutation.ResourceKey, mutation.Request)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	raw, hash, _ := metadataPayload(shape.Payload)
	sourceKind := metadataMutationValueOrDefault(mutation.Request.SourceKind, "builder")
	sourceID := metadataMutationValueOrDefault(mutation.Request.SourceID, "metadata_publication")
	definition, err := r.publishIdentityDefinition(ctx, tx, mutation.ResourceType, shape.Key, shape, raw, hash, mutation.Request, sourceKind, sourceID)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	now := definition.UpdatedAt
	if err := r.syncLocalizedProjection(ctx, tx, mutation.ResourceType, shape.Key, raw, sourceID, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	return definition, nil
}

func (r MetadataStore) applyDefinitionArchive(ctx context.Context, tx *sql.Tx, mutation metadatamodel.MetadataDefinitionMutation) (metadatamodel.MetadataDefinition, error) {
	if mutation.Request.ExpectedSchemaHash == nil || strings.TrimSpace(*mutation.Request.ExpectedSchemaHash) == "" {
		return metadatamodel.MetadataDefinition{}, &metadatamodel.MetadataDefinitionConflictError{ResourceType: mutation.ResourceType, ResourceKey: mutation.ResourceKey}
	}
	expected := strings.TrimSpace(*mutation.Request.ExpectedSchemaHash)
	if metadataModuleOwnsDefinition(mutation.ResourceType) {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definitions are read-only from Identity", mutation.ResourceType)
	}
	return r.disableIdentityDefinition(ctx, tx, mutation.ResourceType, mutation.ResourceKey, expected, mutation.Request.SourceID)
}

func (r MetadataStore) insertChangeAudit(ctx context.Context, tx *sql.Tx, event auditmodel.AuditEvent) error {
	return r.insertMetadataChangeAudit(ctx, tx, event)
}

func (r MetadataStore) syncLocalizedProjection(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string, payload []byte, sourceID, now string) error {
	return r.syncMetadataLocalizedTextTx(ctx, tx, resourceType, resourceKey, payload, sourceID, now)
}

func (r MetadataStore) RollbackDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string, request metadatamodel.MetadataDefinitionRollbackRequest, audit auditmodel.AuditEvent, publication *metadatamodel.MetadataDefinitionPublication) (metadatamodel.MetadataDefinition, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	moduleOwned := metadataModuleOwnsDefinition(resourceType)
	if moduleOwned {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("Metadata-owned %s definition rollback is unavailable from Identity", resourceType)
	}
	tx, err := r.database().BeginTx(ctx, recordMutationTxOptions())
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("begin rollback: %w", err)
	}
	defer tx.Rollback()
	definitions, err := r.identityDefinitions()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	version, found, err := definitions.GetVersion(sharedIdentityDefinitionContext(ctx, tx), shareddefinition.VersionQuery{
		Owner: shareddefinition.OwnerIdentity, ResourceType: resourceType, ResourceKey: resourceKey, SchemaVersion: request.TargetVersion,
	})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback read version: %w", err)
	}
	if !found {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("metadata.version.notFound: %s@%s", resourceKey, request.TargetVersion)
	}
	payloadJSON, targetHash := string(version.Payload), version.SchemaHash
	shape, err := metadataDefinitionShape(ctx, resourceType, resourceKey, metadatamodel.MetadataDefinitionUpsertRequest{Payload: json.RawMessage(payloadJSON)})
	if err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("rollback decode target: %w", err)
	}
	expected := strings.TrimSpace(request.ExpectedSchemaHash)
	rolledBack, err := r.publishIdentityDefinition(ctx, tx, resourceType, resourceKey, shape, []byte(payloadJSON), targetHash, metadatamodel.MetadataDefinitionUpsertRequest{
		Payload: json.RawMessage(payloadJSON), SourceKind: "rollback", SourceID: request.SourceID, ExpectedSchemaHash: &expected,
	}, "rollback", "metadata_rollback")
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	now := rolledBack.UpdatedAt
	if err := r.syncLocalizedProjection(ctx, tx, resourceType, resourceKey, []byte(payloadJSON), request.SourceID, now); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := r.applyIdentityRoleProjectionMutation(ctx, tx, publication, metadatamodel.MetadataDefinitionMutation{Operation: "update", ResourceType: resourceType, ResourceKey: resourceKey}, rolledBack); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := r.insertChangeAudit(ctx, tx, audit); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	if err := r.refreshCatalogHashTx(ctx, tx, now); err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("refresh metadata catalog hash during rollback: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return metadatamodel.MetadataDefinition{}, fmt.Errorf("commit rollback: %w", err)
	}
	definition, _, err := r.GetDefinition(ctx, scope, resourceType, resourceKey)
	return definition, err
}
