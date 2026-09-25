package permission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
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
	QueryIdentityRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	backend Backend
	now     func() string
}

type reconcileExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
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

func (store *Store) Get(ctx context.Context, workspaceID, permissionKey string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityPermissionDefinitionRecord{}, false, err
	}
	permissionKey = strings.TrimSpace(permissionKey)
	if permissionKey == "" {
		return identitymodel.IdentityPermissionDefinitionRecord{}, false, fmt.Errorf("Identity permission key is required")
	}
	statement, arguments, err := permissionSelectBuilder(store.backend.SQLRenderer(), workspaceID).
		Where(query.Equal("permission_key", permissionKey)).Build()
	if err != nil {
		return identitymodel.IdentityPermissionDefinitionRecord{}, false, fmt.Errorf("build Identity permission get: %w", err)
	}
	definition, err := scanPermissionDefinition(store.backend.QueryIdentityRowContext(ctx, statement, arguments...))
	if err == sql.ErrNoRows {
		return identitymodel.IdentityPermissionDefinitionRecord{}, false, nil
	}
	return definition, err == nil, err
}

// SetEnabled mutates only administrator-owned current state. Definition
// content, source ownership, lifecycle and reconcile hashes remain controlled
// by the source owner. A surrounding host transaction, when present, owns the
// commit/rollback together with last-admin checks and audit work.
func (store *Store) SetEnabled(ctx context.Context, workspaceID, permissionKey string, enabled bool) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	permissionKey = strings.TrimSpace(permissionKey)
	if permissionKey == "" {
		return false, fmt.Errorf("Identity permission key is required")
	}
	statement, arguments, err := permissionEnablementBuilder(store.backend.SQLRenderer(), workspaceID, permissionKey, enabled, store.now()).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity permission enablement: %w", err)
	}
	executor := reconcileExecutor(store.backend.DB())
	if hostExecutor := transaction.ExecutorFromContext(ctx); hostExecutor != nil {
		executor = hostExecutor
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, fmt.Errorf("set Identity permission %q enabled=%t: %w", permissionKey, enabled, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect Identity permission enablement: %w", err)
	}
	return rows > 0, nil
}

func permissionEnablementBuilder(renderer ormdialect.Renderer, workspaceID, permissionKey string, enabled bool, now string) *query.UpdateBuilder {
	return query.NewWorkspaceUpdateBuilder(renderer, "_identity_permissions", workspaceID).
		Set("enabled", enabled).
		Set("updated_at", timevalue.Millis(now)).
		Where(query.And(
			query.Equal("permission_key", permissionKey),
			query.Equal("definition_status", identitymodel.IdentityPermissionDefinitionActive),
			query.NotEqual("enabled", enabled),
		))
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
		return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_reconcile_scope_invalid"}
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
	if executor := transaction.ExecutorFromContext(ctx); executor != nil {
		return store.reconcileWithExecutor(ctx, executor, request, incoming)
	}
	tx, err := store.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	defer func() { _ = tx.Rollback() }()
	receipt, err := store.reconcileWithExecutor(ctx, tx, request, incoming)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	return receipt, nil
}

// reconcileWithExecutor participates in the host transaction when one is
// carried by the context. Transaction lifecycle remains with that host; the
// standalone fallback above owns and commits its local transaction.
func (store *Store) reconcileWithExecutor(ctx context.Context, executor reconcileExecutor, request identitymodel.IdentityPermissionReconcileRequest, incoming map[string]identitymodel.IdentityPermissionDefinitionRecord) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	current, err := listWithExecutor(ctx, executor, store.backend.SQLRenderer(), request.WorkspaceID)
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
			return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindInternal, Code: "identity.permission_snapshot_inconsistent", Params: map[string]string{"source_owner": request.SourceOwner}}
		}
	}
	receipt := identitymodel.IdentityPermissionReconcileReceipt{
		WorkspaceID: request.WorkspaceID, SourceOwner: request.SourceOwner,
		PreviousSnapshotHash: currentSnapshotHash, SnapshotHash: request.SnapshotHash, DefinitionCount: len(incoming),
	}
	if request.SnapshotHash == currentSnapshotHash {
		receipt.Unchanged = len(incoming)
		return receipt, nil
	}
	if request.PreviousSnapshotHash != currentSnapshotHash {
		return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "identity.permission_snapshot_stale", Params: map[string]string{"source_owner": request.SourceOwner, "previous_snapshot_hash": request.PreviousSnapshotHash, "current_snapshot_hash": currentSnapshotHash}}
	}
	keys := make([]string, 0, len(incoming))
	for key := range incoming {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		currentDefinition, exists := currentByKey[key]
		if exists && currentDefinition.SourceOwner != request.SourceOwner {
			return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "identity.permission_owner_conflict", Params: map[string]string{"permission_key": key, "current_owner": currentDefinition.SourceOwner, "source_owner": request.SourceOwner}}
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
	if err := retireOwnerDefinitions(ctx, executor, store.backend.SQLRenderer(), request.WorkspaceID, request.SourceOwner, request.SnapshotHash, now); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if err := upsertDefinitions(ctx, executor, store.backend, request.WorkspaceID, keys, incoming, now); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	return receipt, nil
}

func permissionSelectBuilder(renderer ormdialect.Renderer, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(renderer, "_identity_permissions", workspaceID).
		Columns("id", "workspace_id", "permission_key", "resource_key", "operation_key", "label", "description", "category", "source_kind", "source_owner", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at")
}

func permissionListBuilder(renderer ormdialect.Renderer, workspaceID string) *query.SelectBuilder {
	return permissionSelectBuilder(renderer, workspaceID).OrderBy(query.Ascending("permission_key"))
}

func listWithExecutor(ctx context.Context, executor reconcileExecutor, renderer ormdialect.Renderer, workspaceID string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	statement, arguments, err := permissionListBuilder(renderer, workspaceID).Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity permission reconcile list: %w", err)
	}
	rows, err := executor.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissionDefinitions(rows)
}

func scanPermissionDefinitions(rows *sql.Rows) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	out := []identitymodel.IdentityPermissionDefinitionRecord{}
	for rows.Next() {
		definition, err := scanPermissionDefinition(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, definition)
	}
	return out, rows.Err()
}

type permissionDefinitionScanner interface {
	Scan(...any) error
}

func scanPermissionDefinition(scanner permissionDefinitionScanner) (identitymodel.IdentityPermissionDefinitionRecord, error) {
	var definition identitymodel.IdentityPermissionDefinitionRecord
	var createdAt, updatedAt int64
	err := scanner.Scan(
		&definition.ID, &definition.WorkspaceID, &definition.PermissionKey, &definition.ResourceKey, &definition.OperationKey,
		&definition.Label, &definition.Description, &definition.Category, &definition.SourceKind, &definition.SourceOwner,
		&definition.DefinitionStatus, &definition.Enabled, &definition.DefinitionHash, &definition.SourceSnapshotHash,
		&createdAt, &updatedAt,
	)
	definition.CreatedAt, definition.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
	return definition, err
}

func retireOwnerDefinitions(ctx context.Context, executor reconcileExecutor, renderer ormdialect.Renderer, workspaceID, sourceOwner, snapshotHash, now string) error {
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(renderer, "_identity_permissions", workspaceID).
		Set("definition_status", identitymodel.IdentityPermissionDefinitionRetired).
		Set("source_snapshot_hash", snapshotHash).
		Set("updated_at", timevalue.Millis(now)).
		Where(query.Equal("source_owner", sourceOwner)).
		Build()
	if err != nil {
		return fmt.Errorf("build Identity permission owner retirement: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("retire Identity permission owner %q: %w", sourceOwner, err)
	}
	return nil
}

func upsertDefinitions(ctx context.Context, executor reconcileExecutor, backend Backend, workspaceID string, keys []string, incoming map[string]identitymodel.IdentityPermissionDefinitionRecord, now string) error {
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
		if _, execErr := executor.ExecContext(ctx, statement, arguments...); execErr != nil {
			return fmt.Errorf("upsert Identity permission batch: %w", execErr)
		}
	}
	return nil
}

func permissionUpsertBuilder(backend Backend, workspaceID string, keys []string, incoming map[string]identitymodel.IdentityPermissionDefinitionRecord, now string) *query.InsertBuilder {
	insert := query.NewWorkspaceInsertBuilder(backend.SQLRenderer(), "_identity_permissions", workspaceID).
		Columns("id", "permission_key", "resource_key", "operation_key", "label", "description", "category", "source_kind", "source_owner", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at")
	for _, key := range keys {
		definition := incoming[key]
		insert.Values(
			permissionRowID(workspaceID, key), key, definition.ResourceKey, definition.OperationKey,
			definition.Label, definition.Description, definition.Category, definition.SourceKind, definition.SourceOwner,
			identitymodel.IdentityPermissionDefinitionActive, true, definition.DefinitionHash, definition.SourceSnapshotHash,
			timevalue.Millis(now), timevalue.Millis(now),
		)
	}
	return backend.ApplyUpsert(insert, []string{"workspace_id", "permission_key"},
		"resource_key", "operation_key", "label", "description", "category", "source_kind", "source_owner",
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
