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
	sharedoperation "github.com/domainry/domainry-foundation/operation"
	"github.com/domainry/domainry-foundation/requestcontext"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type WriteFenceStore struct {
	db                    *sql.DB
	operations            *sharedoperation.SQLStore
	auditAppender         auditmodel.PreparedAppender
	operationsPersistence atomic.Bool
}

func NewWriteFenceStore(db *sql.DB, renderer ormdialect.Renderer) *WriteFenceStore {
	return &WriteFenceStore{db: db, operations: sharedoperation.NewSQLStore(db, renderer)}
}

func (store *WriteFenceStore) BindAuditPreparedAppender(appender auditmodel.PreparedAppender) {
	if store != nil {
		store.auditAppender = appender
	}
}

const (
	workspaceControlSystemPurpose     = "workspace_control"
	workspaceWriteFenceControlKind    = "write_fence"
	workspaceWriteFenceControlReason  = "identity portability cutover"
	workspaceOperationControlActive   = "active"
	workspaceOperationControlInactive = "inactive"
	identityWriteFenceEventFrozen     = "frozen"
	identityWriteFenceEventReleased   = "released"
)

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
	txctx := sharedoperation.WithExecutor(ctx, tx)
	existing, found, err := store.workspaceWriteControl(txctx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if found && existing.State == workspaceOperationControlActive {
		if existing.Reference == fence.EvidenceSHA256 {
			return identityWriteFenceFromControl(workspaceID, existing), nil
		}
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_already_active")
	}
	expectedRevision, revision := int64(0), int64(1)
	if found {
		expectedRevision, revision = existing.Revision, existing.Revision+1
	}
	changed, err := store.operations.PutControl(txctx, sharedoperation.Control{
		SystemPurpose: workspaceControlSystemPurpose, Kind: workspaceWriteFenceControlKind, Owner: workspaceID,
		State: workspaceOperationControlActive, Reason: workspaceWriteFenceControlReason, Reference: fence.EvidenceSHA256,
		UpdatedBy: operator, Revision: revision, UpdatedAt: fence.FrozenAt,
	}, expectedRevision)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if !changed {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_revision_conflict")
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
	txctx := sharedoperation.WithExecutor(ctx, tx)
	control, found, err := store.workspaceWriteControl(txctx, workspaceID)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if !found || control.State != workspaceOperationControlActive {
		return portabilitymodel.WriteFence{}, fmt.Errorf("identity.portability_write_fence_not_active")
	}
	fence := identityWriteFenceFromControl(workspaceID, control)
	changed, err := store.operations.PutControl(txctx, sharedoperation.Control{
		SystemPurpose: workspaceControlSystemPurpose, Kind: workspaceWriteFenceControlKind, Owner: workspaceID,
		State: workspaceOperationControlInactive, Reason: workspaceWriteFenceControlReason, Reference: control.Reference,
		UpdatedBy: operator, Revision: control.Revision + 1, UpdatedAt: releasedAt,
	}, control.Revision)
	if err != nil {
		return portabilitymodel.WriteFence{}, err
	}
	if !changed {
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
	control, found, err := store.workspaceWriteControl(ctx, strings.TrimSpace(workspaceID))
	if err != nil || !found {
		return portabilitymodel.WriteFence{}, found, err
	}
	return identityWriteFenceFromControl(strings.TrimSpace(workspaceID), control), true, nil
}

func (store *WriteFenceStore) workspaceWriteControl(ctx context.Context, workspaceID string) (sharedoperation.Control, bool, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	control, found, err := store.operations.GetControl(ctx, workspaceControlSystemPurpose, workspaceWriteFenceControlKind, workspaceID)
	if err != nil {
		return sharedoperation.Control{}, false, err
	}
	if !found {
		return sharedoperation.Control{}, false, nil
	}
	if (control.State != workspaceOperationControlActive && control.State != workspaceOperationControlInactive) || strings.TrimSpace(control.Reference) == "" || strings.TrimSpace(control.UpdatedBy) == "" || control.Revision <= 0 {
		return sharedoperation.Control{}, false, fmt.Errorf("identity shared workspace operation control invalid")
	}
	return control, true, nil
}

func identityWriteFenceFromControl(workspaceID string, control sharedoperation.Control) portabilitymodel.WriteFence {
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
		ObjectKey:      sharedoperation.ControlTableName,
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
	if store.auditAppender == nil {
		return fmt.Errorf("Identity Audit module binding is unavailable")
	}
	if err := store.auditAppender.AppendPreparedWithin(ctx, writeFenceAuditTransaction{tx: tx}, auditEvent); err != nil {
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
	return store.operations.ControlStateExists(ctx, workspaceControlSystemPurpose, workspaceWriteFenceControlKind, workspaceOperationControlActive)
}
