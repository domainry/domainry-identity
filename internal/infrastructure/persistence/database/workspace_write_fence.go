package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
)

const (
	identityWorkspaceWriteFenceTable   = "identity_workspace_write_fences"
	identityPortabilityFenceEventTable = "identity_portability_write_fence_events"
	identityWriteFenceEventFrozen      = "frozen"
	identityWriteFenceEventReleased    = "released"
)

type identityWriteFenceQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (store *IdentityStore) FreezeIdentityWrites(ctx context.Context, workspaceID, evidence, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.tableIdentifier(identityWorkspaceWriteFenceTable)+" WHERE "+store.identifier("workspace_id")+" = "+store.placeholder(1), workspaceID); err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	columns := []string{"workspace_id", "state", "evidence_sha256", "frozen_by", "frozen_at", "released_by", "released_at", "updated_at"}
	query := "INSERT INTO " + store.tableIdentifier(identityWorkspaceWriteFenceTable) + " (" + strings.Join(quotedColumns(store, columns), ", ") + ") VALUES (" + strings.Join(placeholders(store, len(columns)), ", ") + ")"
	if _, err := tx.ExecContext(ctx, query, fence.WorkspaceID, fence.State, fence.EvidenceSHA256, fence.FrozenBy, fence.FrozenAt.Format(time.RFC3339Nano), "", nil, fence.FrozenAt.Format(time.RFC3339Nano)); err != nil {
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

func (store *IdentityStore) ReleaseIdentityWriteFence(ctx context.Context, workspaceID, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
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
	query := "UPDATE " + store.tableIdentifier(identityWorkspaceWriteFenceTable) + " SET " + store.identifier("state") + " = 'released', " + store.identifier("released_by") + " = " + store.placeholder(1) + ", " + store.identifier("released_at") + " = " + store.placeholder(2) + ", " + store.identifier("updated_at") + " = " + store.placeholder(3) + " WHERE " + store.identifier("workspace_id") + " = " + store.placeholder(4) + " AND " + store.identifier("state") + " = 'frozen' AND " + store.identifier("evidence_sha256") + " = " + store.placeholder(5)
	result, err := tx.ExecContext(ctx, query, operator, releasedAt.Format(time.RFC3339Nano), releasedAt.Format(time.RFC3339Nano), workspaceID, fence.EvidenceSHA256)
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

func (store *IdentityStore) IdentityWriteFence(ctx context.Context, workspaceID string) (portabilitymodel.WriteFence, bool, error) {
	return store.identityWriteFence(ctx, store.db, workspaceID)
}

func (store *IdentityStore) identityWriteFence(ctx context.Context, queryer identityWriteFenceQueryer, workspaceID string) (portabilitymodel.WriteFence, bool, error) {
	query := "SELECT " + strings.Join(quotedColumns(store, []string{"state", "evidence_sha256", "frozen_by", "frozen_at", "released_by", "released_at"}), ", ") + " FROM " + store.tableIdentifier(identityWorkspaceWriteFenceTable) + " WHERE " + store.identifier("workspace_id") + " = " + store.placeholder(1)
	var fence portabilitymodel.WriteFence
	var frozenAt string
	var releasedAt sql.NullString
	err := queryer.QueryRowContext(ctx, query, strings.TrimSpace(workspaceID)).Scan(&fence.State, &fence.EvidenceSHA256, &fence.FrozenBy, &frozenAt, &fence.ReleasedBy, &releasedAt)
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

func (store *IdentityStore) appendIdentityWriteFenceEvent(ctx context.Context, tx *sql.Tx, workspaceID, event, evidenceSHA256, operator string, occurredAt time.Time) error {
	digest := sha256.Sum256([]byte(strings.Join([]string{workspaceID, event, evidenceSHA256, operator, occurredAt.UTC().Format(time.RFC3339Nano)}, "\x00")))
	columns := []string{"event_id", "workspace_id", "event", "evidence_sha256", "operator", "occurred_at"}
	query := "INSERT INTO " + store.tableIdentifier(identityPortabilityFenceEventTable) + " (" + strings.Join(quotedColumns(store, columns), ", ") + ") VALUES (" + strings.Join(placeholders(store, len(columns)), ", ") + ")"
	if _, err := tx.ExecContext(ctx, query, hex.EncodeToString(digest[:]), workspaceID, event, evidenceSHA256, operator, occurredAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("append Identity write-fence event: %w", err)
	}
	return nil
}

func (store *IdentityStore) IdentityWritesFrozen(ctx context.Context, workspaceID string) (bool, error) {
	fence, found, err := store.IdentityWriteFence(ctx, workspaceID)
	return found && fence.State == "frozen", err
}

func (store *IdentityStore) AnyIdentityWritesFrozen(ctx context.Context) (bool, error) {
	query := "SELECT COUNT(*) FROM " + store.tableIdentifier(identityWorkspaceWriteFenceTable) + " WHERE " + store.identifier("state") + " = 'frozen'"
	var count int64
	if err := store.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (store *IdentityStore) VerifyIdentityWriteFreeze(ctx context.Context, workspaceID, evidence string) error {
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
