package permission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/batch"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	MaxParameters() int
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store {
	return &Store{backend: backend, now: now}
}

func (store *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := permissionListBuilder(store.backend.SQLRenderer(), workspaceID).Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity permission list: %w", err)
	}
	rows, err := store.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissionDefinitions(rows)
}

func (store *Store) Reconcile(ctx context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	workspaceID, err := workspace(request.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	request.WorkspaceID = workspaceID
	request.SourceOwner = strings.TrimSpace(request.SourceOwner)
	request.PreviousSnapshotHash = strings.TrimSpace(request.PreviousSnapshotHash)
	request.SnapshotHash = strings.TrimSpace(request.SnapshotHash)
	if request.SourceOwner == "" || request.SnapshotHash == "" {
		return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission source owner and snapshot hash are required")
	}
	incoming := make(map[string]identitymodel.IdentityPermissionDefinitionRecord, len(request.Definitions))
	for _, definition := range request.Definitions {
		definition.WorkspaceID = strings.TrimSpace(definition.WorkspaceID)
		definition.PermissionKey = strings.TrimSpace(definition.PermissionKey)
		definition.SourceOwner = strings.TrimSpace(definition.SourceOwner)
		definition.SourceSnapshotHash = strings.TrimSpace(definition.SourceSnapshotHash)
		if definition.WorkspaceID != workspaceID || definition.SourceOwner != request.SourceOwner || definition.SourceSnapshotHash != request.SnapshotHash || definition.PermissionKey == "" || strings.TrimSpace(definition.DefinitionHash) == "" {
			return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission definition %q does not match its reconcile scope", definition.PermissionKey)
		}
		if _, duplicate := incoming[definition.PermissionKey]; duplicate {
			return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission definition %q is duplicated", definition.PermissionKey)
		}
		incoming[definition.PermissionKey] = definition
	}
	tx, err := store.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := listWithExecutor(ctx, tx, store.backend.SQLRenderer(), workspaceID)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	currentSnapshotHash := ""
	currentByKey := make(map[string]identitymodel.IdentityPermissionDefinitionRecord, len(current))
	for _, definition := range current {
		currentByKey[definition.PermissionKey] = definition
		if definition.SourceOwner != request.SourceOwner {
			continue
		}
		if currentSnapshotHash == "" {
			currentSnapshotHash = definition.SourceSnapshotHash
		} else if currentSnapshotHash != definition.SourceSnapshotHash {
			return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission owner %q has inconsistent snapshot hashes", request.SourceOwner)
		}
	}
	if request.PreviousSnapshotHash != currentSnapshotHash {
		return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission snapshot is stale: previous=%q current=%q", request.PreviousSnapshotHash, currentSnapshotHash)
	}
	receipt := identitymodel.IdentityPermissionReconcileReceipt{WorkspaceID: workspaceID, SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash}
	if request.SnapshotHash == currentSnapshotHash {
		receipt.Unchanged = len(incoming)
		return receipt, tx.Commit()
	}
	keys := make([]string, 0, len(incoming))
	for key := range incoming {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		currentDefinition, exists := currentByKey[key]
		if exists && currentDefinition.SourceOwner != request.SourceOwner {
			return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission %q is owned by %q, not %q", key, currentDefinition.SourceOwner, request.SourceOwner)
		}
		if !exists {
			receipt.Inserted++
			continue
		}
		receipt.Updated++
	}
	for _, definition := range current {
		if definition.SourceOwner != request.SourceOwner {
			continue
		}
		if _, retained := incoming[definition.PermissionKey]; retained {
			continue
		}
		if definition.DefinitionStatus != identitymodel.IdentityPermissionDefinitionRetired {
			receipt.Retired++
		} else {
			receipt.Updated++
		}
	}
	now := store.now()
	// Reconcile is deliberately set-oriented: retire the owner's current set in
	// one statement, then reactivate/insert the submitted snapshot with bounded
	// multi-row upserts. The transaction prevents observers from seeing the
	// intermediate retired state and avoids one database round-trip per key.
	if err := retireOwnerDefinitions(ctx, tx, store.backend.SQLRenderer(), workspaceID, request.SourceOwner, request.SnapshotHash, now); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if err := upsertDefinitions(ctx, tx, store.backend, workspaceID, keys, incoming, now); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	return receipt, nil
}

func permissionListBuilder(renderer ormdialect.Renderer, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(renderer, "_identity_permissions", workspaceID).
		Columns("id", "workspace_id", "permission_key", "resource_key", "action_key", "label", "description", "category", "source_kind", "source_owner", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at").
		OrderBy(query.Ascending("permission_key"))
}

func listWithExecutor(ctx context.Context, tx *sql.Tx, renderer ormdialect.Renderer, workspaceID string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	statement, arguments, err := permissionListBuilder(renderer, workspaceID).Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity permission reconcile list: %w", err)
	}
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissionDefinitions(rows)
}

func scanPermissionDefinitions(rows *sql.Rows) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	out := []identitymodel.IdentityPermissionDefinitionRecord{}
	for rows.Next() {
		var definition identitymodel.IdentityPermissionDefinitionRecord
		if err := rows.Scan(
			&definition.ID, &definition.WorkspaceID, &definition.PermissionKey, &definition.ResourceKey, &definition.ActionKey,
			&definition.Label, &definition.Description, &definition.Category, &definition.SourceKind, &definition.SourceOwner,
			&definition.DefinitionStatus, &definition.Enabled, &definition.DefinitionHash, &definition.SourceSnapshotHash,
			&definition.CreatedAt, &definition.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, definition)
	}
	return out, rows.Err()
}

func retireOwnerDefinitions(ctx context.Context, tx *sql.Tx, renderer ormdialect.Renderer, workspaceID, sourceOwner, snapshotHash, now string) error {
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(renderer, "_identity_permissions", workspaceID).
		Set("definition_status", identitymodel.IdentityPermissionDefinitionRetired).
		Set("source_snapshot_hash", snapshotHash).
		Set("updated_at", now).
		Where(query.Equal("source_owner", sourceOwner)).
		Build()
	if err != nil {
		return fmt.Errorf("build Identity permission owner retirement: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("retire Identity permission owner %q: %w", sourceOwner, err)
	}
	return nil
}

func upsertDefinitions(ctx context.Context, tx *sql.Tx, backend Backend, workspaceID string, keys []string, incoming map[string]identitymodel.IdentityPermissionDefinitionRecord, now string) error {
	const parametersPerRow = 16 // workspace_id plus the fifteen explicit columns below.
	ranges, err := (batch.Parameters{Max: backend.MaxParameters(), PerItem: parametersPerRow}).Ranges(len(keys))
	if err != nil {
		return fmt.Errorf("plan Identity permission upsert batches: %w", err)
	}
	for _, batchRange := range ranges {
		insert := permissionUpsertBuilder(backend, workspaceID, keys[batchRange.Start:batchRange.End], incoming, now)
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return fmt.Errorf("build Identity permission batch upsert: %w", buildErr)
		}
		if _, execErr := tx.ExecContext(ctx, statement, arguments...); execErr != nil {
			return fmt.Errorf("upsert Identity permission batch: %w", execErr)
		}
	}
	return nil
}

func permissionUpsertBuilder(backend Backend, workspaceID string, keys []string, incoming map[string]identitymodel.IdentityPermissionDefinitionRecord, now string) *query.InsertBuilder {
	insert := query.NewWorkspaceInsertBuilder(backend.SQLRenderer(), "_identity_permissions", workspaceID).
		Columns("id", "permission_key", "resource_key", "action_key", "label", "description", "category", "source_kind", "source_owner", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at")
	for _, key := range keys {
		definition := incoming[key]
		insert.Values(
			permissionRowID(workspaceID, key), key, definition.ResourceKey, definition.ActionKey,
			definition.Label, definition.Description, definition.Category, definition.SourceKind, definition.SourceOwner,
			identitymodel.IdentityPermissionDefinitionActive, true, definition.DefinitionHash, definition.SourceSnapshotHash,
			now, now,
		)
	}
	return backend.ApplyUpsert(insert, []string{"workspace_id", "permission_key"},
		"resource_key", "action_key", "label", "description", "category", "source_kind", "source_owner",
		"definition_status", "definition_hash", "source_snapshot_hash", "updated_at",
	)
}

func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func permissionRowID(workspaceID, permissionKey string) string {
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + permissionKey))
	return "permission-" + hex.EncodeToString(sum[:16])
}
