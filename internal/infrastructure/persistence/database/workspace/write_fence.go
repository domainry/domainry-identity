package workspace

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	"github.com/domainry/domainry-foundation/requestcontext"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type WriteFenceStore struct {
	db                    *sql.DB
	renderer              ormdialect.Renderer
	operationsPersistence atomic.Bool
}

func NewWriteFenceStore(db *sql.DB, renderer ormdialect.Renderer) *WriteFenceStore {
	return &WriteFenceStore{db: db, renderer: renderer}
}

const (
	sharedOperationControlsTable      = "_operation_controls"
	workspaceControlSystemPurpose     = "workspace_control"
	workspaceWriteFenceControlKind    = "write_fence"
	workspaceWriteFenceControlReason  = "identity portability cutover"
	workspaceOperationControlActive   = "active"
	workspaceOperationControlInactive = "inactive"
	identityWriteFenceEventFrozen     = "frozen"
	identityWriteFenceEventReleased   = "released"
)

type workspaceOperationControlQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type workspaceOperationControl struct {
	State     string
	Reference string
	UpdatedBy string
	Revision  int64
	UpdatedAt time.Time
}

func (store *WriteFenceStore) BindOperationsPersistence() {
	if store != nil {
		store.operationsPersistence.Store(true)
	}
}

func (store *WriteFenceStore) OperationsPersistenceBound() bool {
	return store != nil && store.operationsPersistence.Load()
}

func (store *WriteFenceStore) FreezeIdentityWrites(ctx context.Context, workspaceID, evidence, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	workspaceID, evidence, operator = strings.TrimSpace(workspaceID), strings.TrimSpace(evidence), strings.TrimSpace(operator)
	if workspaceID == "" || evidence == "" || operator == "" {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_freeze_fields_required")
	}
	if !store.OperationsPersistenceBound() {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity shared workspace operation control persistence is not bound")
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
	existing, found, err := store.workspaceWriteControl(ctx, tx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if found && existing.State == workspaceOperationControlActive {
		if existing.Reference == fence.EvidenceSHA256 {
			return identityWriteFenceFromControl(workspaceID, existing), nil
		}
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_already_active")
	}
	if !found {
		statement, arguments, buildErr := query.NewInsertBuilder(store.renderer, sharedOperationControlsTable).
			Columns("system_purpose", "control_kind", "owner", "state", "reason", "reference", "updated_by", "revision", "updated_at").
			Values(workspaceControlSystemPurpose, workspaceWriteFenceControlKind, workspaceID, workspaceOperationControlActive, workspaceWriteFenceControlReason, fence.EvidenceSHA256, operator, int64(1), fence.FrozenAt.Format(time.RFC3339Nano)).Build()
		if buildErr != nil {
			return portabilitymodel.WriteFence{}, fmt.Errorf("build shared workspace write control insert: %w", buildErr)
		}
		if _, err = tx.ExecContext(ctx, statement, arguments...); err != nil {
			return portabilitymodel.WriteFence{}, err
		}
	} else {
		statement, arguments, buildErr := query.NewUpdateBuilder(store.renderer, sharedOperationControlsTable).
			Set("state", workspaceOperationControlActive).Set("reason", workspaceWriteFenceControlReason).
			Set("reference", fence.EvidenceSHA256).Set("updated_by", operator).
			Set("revision", existing.Revision+1).Set("updated_at", fence.FrozenAt.Format(time.RFC3339Nano)).
			Where(query.And(
				query.Equal("system_purpose", workspaceControlSystemPurpose),
				query.Equal("control_kind", workspaceWriteFenceControlKind),
				query.Equal("owner", workspaceID),
				query.Equal("revision", existing.Revision),
			)).Build()
		if buildErr != nil {
			return portabilitymodel.WriteFence{}, fmt.Errorf("build shared workspace write control activation: %w", buildErr)
		}
		result, execErr := tx.ExecContext(ctx, statement, arguments...)
		if execErr != nil {
			return portabilitymodel.WriteFence{}, execErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return portabilitymodel.WriteFence{}, rowsErr
		}
		if rows != 1 {
			return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_revision_conflict")
		}
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
	if !store.OperationsPersistenceBound() {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity shared workspace operation control persistence is not bound")
	}
	releasedAt := now.UTC()
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	defer tx.Rollback()
	control, found, err := store.workspaceWriteControl(ctx, tx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if !found || control.State != workspaceOperationControlActive {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_not_active")
	}
	fence := identityWriteFenceFromControl(workspaceID, control)
	queryValue, arguments, err := query.NewUpdateBuilder(store.renderer, sharedOperationControlsTable).
		Set("state", workspaceOperationControlInactive).Set("reason", workspaceWriteFenceControlReason).
		Set("reference", control.Reference).Set("updated_by", operator).
		Set("revision", control.Revision+1).Set("updated_at", releasedAt.Format(time.RFC3339Nano)).
		Where(query.And(
			query.Equal("system_purpose", workspaceControlSystemPurpose),
			query.Equal("control_kind", workspaceWriteFenceControlKind),
			query.Equal("owner", workspaceID),
			query.Equal("state", workspaceOperationControlActive),
			query.Equal("revision", control.Revision),
		)).Build()
	if err != nil {
		return portabilitymodel.WriteFence{}, fmt.Errorf("build shared workspace write control release: %w", err)
	}
	result, err := tx.ExecContext(ctx, queryValue, arguments...)
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
	if !store.OperationsPersistenceBound() {
		return portabilitymodel.WriteFence{}, false, fmt.Errorf("identity shared workspace operation control persistence is not bound")
	}
	control, found, err := store.workspaceWriteControl(ctx, store.db, strings.TrimSpace(workspaceID))
	if err != nil || !found {
		return portabilitymodel.WriteFence{}, found, err
	}
	return identityWriteFenceFromControl(strings.TrimSpace(workspaceID), control), true, nil
}

func (store *WriteFenceStore) workspaceWriteControl(ctx context.Context, queryer workspaceOperationControlQueryer, workspaceID string) (workspaceOperationControl, bool, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	queryValue, arguments, err := query.NewSelectBuilder(store.renderer, sharedOperationControlsTable).
		Columns("state", "reference", "updated_by", "revision", "updated_at").
		Where(query.And(
			query.Equal("system_purpose", workspaceControlSystemPurpose),
			query.Equal("control_kind", workspaceWriteFenceControlKind),
			query.Equal("owner", workspaceID),
		)).Build()
	if err != nil {
		return workspaceOperationControl{}, false, fmt.Errorf("build shared workspace write control read: %w", err)
	}
	var control workspaceOperationControl
	var updatedAt string
	err = queryer.QueryRowContext(ctx, queryValue, arguments...).Scan(&control.State, &control.Reference, &control.UpdatedBy, &control.Revision, &updatedAt)
	if err == sql.ErrNoRows {
		return workspaceOperationControl{}, false, nil
	}
	if err != nil {
		return workspaceOperationControl{}, false, err
	}
	control.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return workspaceOperationControl{}, false, err
	}
	if (control.State != workspaceOperationControlActive && control.State != workspaceOperationControlInactive) || strings.TrimSpace(control.Reference) == "" || strings.TrimSpace(control.UpdatedBy) == "" || control.Revision <= 0 {
		return workspaceOperationControl{}, false, fmt.Errorf("identity shared workspace operation control invalid")
	}
	return control, true, nil
}

func identityWriteFenceFromControl(workspaceID string, control workspaceOperationControl) portabilitymodel.WriteFence {
	fence := portabilitymodel.WriteFence{WorkspaceID: workspaceID, EvidenceSHA256: control.Reference}
	if control.State == workspaceOperationControlActive {
		fence.State, fence.FrozenBy, fence.FrozenAt = "frozen", control.UpdatedBy, control.UpdatedAt
		return fence
	}
	fence.State, fence.ReleasedBy = "released", control.UpdatedBy
	releasedAt := control.UpdatedAt
	fence.ReleasedAt = &releasedAt
	return fence
}

func (store *WriteFenceStore) appendIdentityWriteFenceEvent(ctx context.Context, tx *sql.Tx, workspaceID, event, evidenceSHA256, operator string, occurredAt time.Time) error {
	stateEvent := "identity.portability_write_fence." + strings.TrimSpace(event)
	auditEvent, err := auditmodel.BuildEvent(auditmodel.AppendRequest{
		IdempotencyKey: strings.Join([]string{"identity-write-fence", event, evidenceSHA256, operator, occurredAt.UTC().Format(time.RFC3339Nano)}, ":"),
		OperationID:    requestcontext.OwnerExecutionID(ctx),
		Family:         auditmodel.EventFamilyIdentityGovernance,
		Event:          stateEvent,
		ObjectKey:      sharedOperationControlsTable,
		RecordID:       workspaceID,
		Actor:          auditmodel.Actor{WorkspaceID: workspaceID, SubjectID: operator, Kind: "operator"},
		Summary:        "Identity portability write fence " + event,
		After: map[string]any{
			"state":           event,
			"evidence_sha256": evidenceSHA256,
		},
	}, occurredAt)
	if err != nil {
		return fmt.Errorf("build Identity write-fence audit event: %w", err)
	}
	if err := auditmoduleimpl.AppendPreparedWithin(ctx, store.renderer, writeFenceAuditTransaction{tx: tx}, auditEvent); err != nil {
		return fmt.Errorf("append Identity write-fence audit event: %w", err)
	}
	return nil
}

type writeFenceAuditTransaction struct{ tx *sql.Tx }

func (adapter writeFenceAuditTransaction) ExecContext(ctx context.Context, queryValue string, arguments ...any) (auditmodel.Result, error) {
	return adapter.tx.ExecContext(ctx, queryValue, arguments...)
}

func (adapter writeFenceAuditTransaction) QueryRowContext(ctx context.Context, queryValue string, arguments ...any) auditmodel.Row {
	return adapter.tx.QueryRowContext(ctx, queryValue, arguments...)
}

func (store *WriteFenceStore) IdentityWritesFrozen(ctx context.Context, workspaceID string) (bool, error) {
	if !store.OperationsPersistenceBound() {
		return false, nil
	}
	fence, found, err := store.IdentityWriteFence(ctx, workspaceID)
	return found && fence.State == "frozen", err
}

func (store *WriteFenceStore) AnyIdentityWritesFrozen(ctx context.Context) (bool, error) {
	if !store.OperationsPersistenceBound() {
		return false, nil
	}
	queryValue, arguments, err := query.NewSelectBuilder(store.renderer, sharedOperationControlsTable).
		Projections(query.Project(query.CountAll())).Where(query.And(
		query.Equal("system_purpose", workspaceControlSystemPurpose),
		query.Equal("control_kind", workspaceWriteFenceControlKind),
		query.Equal("state", workspaceOperationControlActive),
	)).Build()
	if err != nil {
		return false, fmt.Errorf("build active Identity write fence count: %w", err)
	}
	var count int64
	if err := store.db.QueryRowContext(ctx, queryValue, arguments...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
