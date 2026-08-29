package workspace

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type WriteFenceStore struct {
	db       *sql.DB
	renderer ormdialect.Renderer
}

func NewWriteFenceStore(db *sql.DB, renderer ormdialect.Renderer) *WriteFenceStore {
	return &WriteFenceStore{db: db, renderer: renderer}
}

const (
	identityWorkspaceWriteFenceTable   = "identity_workspace_write_fences"
	identityPortabilityFenceEventTable = "identity_portability_write_fence_events"
	identityWriteFenceEventFrozen      = "frozen"
	identityWriteFenceEventReleased    = "released"
)

type identityWriteFenceQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (store *WriteFenceStore) FreezeIdentityWrites(ctx context.Context, workspaceID, evidence, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	workspaceID, evidence, operator = strings.TrimSpace(workspaceID), strings.TrimSpace(evidence), strings.TrimSpace(operator)
	if workspaceID == "" || evidence == "" || operator == "" {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_freeze_fields_required")
	}
	digest := sha256.Sum256([]byte(evidence))
	fence := portabilitymodel.WriteFence{
		WorkspaceID: workspaceID, State: "frozen", EvidenceSHA256: hex.EncodeToString(digest[:]),
		FrozenBy: operator, FrozenAt: now.UTC(),
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	defer tx.Rollback()
	existing, found, err := store.identityWriteFence(ctx, tx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if found && existing.State == "frozen" {
		if existing.EvidenceSHA256 == fence.EvidenceSHA256 {
			return existing, nil
		}
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_already_active")
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(store.renderer, identityWorkspaceWriteFenceTable, workspaceID).Build()
	if err != nil {
		return portabilitymodel.WriteFence{}, fmt.Errorf("build Identity write fence replacement: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceInsertBuilder(store.renderer, identityWorkspaceWriteFenceTable, fence.WorkspaceID).
		Columns("state", "evidence_sha256", "frozen_by", "frozen_at", "released_by", "released_at", "updated_at").
		Values(fence.State, fence.EvidenceSHA256, fence.FrozenBy, fence.FrozenAt.Format(time.RFC3339Nano), "", nil, fence.FrozenAt.Format(time.RFC3339Nano)).Build()
	if err != nil {
		return portabilitymodel.WriteFence{}, fmt.Errorf("build Identity write fence insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if err := store.appendIdentityWriteFenceEvent(ctx, tx, fence.WorkspaceID, identityWriteFenceEventFrozen, fence.EvidenceSHA256, operator, fence.FrozenAt); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if err := tx.Commit(); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	return fence, nil
}

func (store *WriteFenceStore) ReleaseIdentityWriteFence(ctx context.Context, workspaceID, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	workspaceID, operator = strings.TrimSpace(workspaceID), strings.TrimSpace(operator)
	if workspaceID == "" || operator == "" {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_release_fields_required")
	}
	releasedAt := now.UTC()
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	defer tx.Rollback()
	fence, found, err := store.identityWriteFence(ctx, tx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if !found || fence.State != "frozen" {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_not_active")
	}
	query, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(store.renderer, identityWorkspaceWriteFenceTable, workspaceID).
		Set("state", "released").Set("released_by", operator).
		Set("released_at", releasedAt.Format(time.RFC3339Nano)).Set("updated_at", releasedAt.Format(time.RFC3339Nano)).
		Where(ormbuilder.And(ormbuilder.Equal("state", "frozen"), ormbuilder.Equal("evidence_sha256", fence.EvidenceSHA256))).Build()
	if err != nil {
		return portabilitymodel.WriteFence{}, fmt.Errorf("build Identity write fence release: %w", err)
	}
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if rows != 1 {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_not_active")
	}
	if err := store.appendIdentityWriteFenceEvent(ctx, tx, workspaceID, identityWriteFenceEventReleased, fence.EvidenceSHA256, operator, releasedAt); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if err := tx.Commit(); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	fence.State = "released"
	fence.ReleasedBy = operator
	fence.ReleasedAt = &releasedAt
	return fence, nil
}

func (store *WriteFenceStore) IdentityWriteFence(ctx context.Context, workspaceID string) (portabilitymodel.WriteFence, bool, error) {
	return store.identityWriteFence(ctx, store.db, workspaceID)
}

func (store *WriteFenceStore) identityWriteFence(ctx context.Context, queryer identityWriteFenceQueryer, workspaceID string) (portabilitymodel.WriteFence, bool, error) {
	query, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(store.renderer, identityWorkspaceWriteFenceTable, strings.TrimSpace(workspaceID)).
		Columns("state", "evidence_sha256", "frozen_by", "frozen_at", "released_by", "released_at").Build()
	if err != nil {
		return portabilitymodel.WriteFence{}, false, fmt.Errorf("build Identity write fence read: %w", err)
	}
	var fence portabilitymodel.WriteFence
	var frozenAt string
	var releasedAt sql.NullString
	err = queryer.QueryRowContext(ctx, query, arguments...).Scan(&fence.State, &fence.EvidenceSHA256, &fence.FrozenBy, &frozenAt, &fence.ReleasedBy, &releasedAt)
	if err == sql.ErrNoRows {
		return portabilitymodel.WriteFence{}, false, nil
	}
	if err != nil {
		return portabilitymodel.WriteFence{}, false, err
	}
	fence.WorkspaceID = strings.TrimSpace(workspaceID)
	fence.FrozenAt, err = time.Parse(time.RFC3339Nano, frozenAt)
	if err != nil {
		return portabilitymodel.WriteFence{}, false, err
	}
	if releasedAt.Valid && strings.TrimSpace(releasedAt.String) != "" {
		value, parseErr := time.Parse(time.RFC3339Nano, releasedAt.String)
		if parseErr != nil {
			return portabilitymodel.WriteFence{}, false, parseErr
		}
		fence.ReleasedAt = &value
	}
	return fence, true, nil
}

func (store *WriteFenceStore) appendIdentityWriteFenceEvent(ctx context.Context, tx *sql.Tx, workspaceID, event, evidenceSHA256, operator string, occurredAt time.Time) error {
	digest := sha256.Sum256([]byte(strings.Join([]string{workspaceID, event, evidenceSHA256, operator, occurredAt.UTC().Format(time.RFC3339Nano)}, "\x00")))
	query, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(store.renderer, identityPortabilityFenceEventTable, workspaceID).
		Columns("event_id", "event", "evidence_sha256", "operator", "occurred_at").
		Values(hex.EncodeToString(digest[:]), event, evidenceSHA256, operator, occurredAt.UTC().Format(time.RFC3339Nano)).Build()
	if err != nil {
		return fmt.Errorf("build Identity write-fence event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, arguments...); err != nil {
		return fmt.Errorf("append Identity write-fence event: %w", err)
	}
	return nil
}

func (store *WriteFenceStore) IdentityWritesFrozen(ctx context.Context, workspaceID string) (bool, error) {
	fence, found, err := store.IdentityWriteFence(ctx, workspaceID)
	return found && fence.State == "frozen", err
}

func (store *WriteFenceStore) AnyIdentityWritesFrozen(ctx context.Context) (bool, error) {
	query, arguments, err := ormbuilder.NewSelectBuilder(store.renderer, identityWorkspaceWriteFenceTable).
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("state", "frozen")).Build()
	if err != nil {
		return false, fmt.Errorf("build active Identity write fence count: %w", err)
	}
	var count int64
	if err := store.db.QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (store *WriteFenceStore) VerifyIdentityWriteFreeze(ctx context.Context, workspaceID, evidence string) error {
	fence, found, err := store.IdentityWriteFence(ctx, workspaceID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(evidence)))
	if !found || fence.State != "frozen" || fence.EvidenceSHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("identity.portability_write_freeze_not_active")
	}
	return nil
}
