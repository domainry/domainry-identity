package profilebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditcontract "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	OperationsPersistenceBound() bool
	Audit() auditsdk.Binding
}

const (
	profileBindingOperationOwner = "identity"
	profileBindingOperationKind  = "identity.profile_binding"
	profileBindingAuditPrefix    = "identity.profile_binding."
)

func (s *Store) ListIdentityProfileBindingsByUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	statement, arguments, err := profileBindingSelect(s.store, workspaceID).
		Where(query.Equal("identity_user_id", strings.TrimSpace(userID))).
		OrderBy(query.Ascending("object_key"), query.Ascending("profile_id")).
		Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.store.DB().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := []identitymodel.IdentityProfileBinding{}
	for rows.Next() {
		binding, scanErr := scanIdentityProfileBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

type Store struct {
	store Backend
}

func New(store Backend) *Store {
	return &Store{store: store}
}

func (s *Store) GetIdentityProfileBinding(ctx context.Context, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	statement, arguments, err := profileBindingSelect(s.store, workspaceID).
		Where(query.And(query.Equal("object_key", objectKey), query.Equal("profile_id", profileID))).Build()
	if err != nil {
		return identitymodel.IdentityProfileBinding{}, false, err
	}
	binding, err := scanIdentityProfileBinding(s.queryer(ctx).QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *Store) GetIdentityProfileBindingByKey(ctx context.Context, workspaceID, bindingKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	statement, arguments, err := profileBindingSelect(s.store, workspaceID).
		Where(query.And(query.Equal("binding_key", bindingKey), query.Equal("profile_id", profileID))).Build()
	if err != nil {
		return identitymodel.IdentityProfileBinding{}, false, err
	}
	binding, err := scanIdentityProfileBinding(s.queryer(ctx).QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func profileBindingSelect(store Backend, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(store.SQLRenderer(), "_identity_profile_bindings", workspaceID).
		Columns("workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at")
}

func (s *Store) IdentityRoleBindingActive(ctx context.Context, workspaceID, bindingKey, profileID, userID string) (bool, error) {
	binding, found, err := s.GetIdentityProfileBindingByKey(ctx, workspaceID, strings.TrimSpace(bindingKey), strings.TrimSpace(profileID))
	if err != nil || !found {
		return false, err
	}
	return binding.Status == identitymodel.IdentityProfileBindingActive && strings.TrimSpace(binding.IdentityUserID) == strings.TrimSpace(userID), nil
}

func (s *Store) GetIdentityProfileBindingReceipt(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	if !s.store.OperationsPersistenceBound() {
		return identitymodel.IdentityProfileBindingReceipt{}, false, errors.New("identity shared Operations persistence is not bound")
	}
	return s.loadReceipt(ctx, s.queryer(ctx), mutation)
}

func (s *Store) ExecuteIdentityProfileBindingMutation(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	if err := validateIdentityProfileBindingMutation(mutation); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if !s.store.OperationsPersistenceBound() {
		return identitymodel.IdentityProfileBindingReceipt{}, errors.New("identity shared Operations persistence is not bound")
	}
	executor := identitytransaction.ExecutorFromContext(ctx)
	if mutation.ProfileRecordStaged && executor == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_transaction_required")
	}
	if executor != nil {
		return s.executeIdentityProfileBindingMutation(ctx, executor, mutation)
	}
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	defer tx.Rollback()
	receipt, err := s.executeIdentityProfileBindingMutation(ctx, tx, mutation)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	return receipt, nil
}

func (s *Store) executeIdentityProfileBindingMutation(ctx context.Context, executor identitytransaction.Executor, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	if receipt, found, loadErr := s.loadReceipt(ctx, executor, mutation); loadErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Replayed = true
		return receipt, nil
	}
	currentUserID := ""
	if !mutation.ProfileRecordStaged {
		var err error
		currentUserID, err = s.loadProfileIdentityUser(ctx, executor, mutation)
		if errors.Is(err, sql.ErrNoRows) {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindNotFound, "backend.identity.profile_not_found")
		}
		if err != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, err
		}
	}
	current, found, err := s.loadBinding(ctx, executor, mutation.WorkspaceID, mutation.ObjectKey, mutation.ProfileID)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	currentVersion := int64(0)
	createdAt := profileBindingNow()
	if found {
		currentVersion, createdAt = current.Version, current.CreatedAt
	}
	if currentVersion != mutation.ExpectedVersion {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_binding_version_conflict")
	}
	var status identitymodel.IdentityProfileBindingStatus
	var desiredUserID string

	adoptExistingRelation := !found && mutation.Operation == identitymodel.IdentityProfileBindingBind &&
		currentUserID != "" && currentUserID == strings.TrimSpace(mutation.IdentityUserID)
	if adoptExistingRelation {
		status, desiredUserID = identitymodel.IdentityProfileBindingActive, currentUserID
	} else {
		var transitionErr error
		status, desiredUserID, transitionErr = identityProfileBindingTransition(mutation, currentUserID)
		if transitionErr != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, transitionErr
		}
	}
	now := profileBindingNow()
	next := identitymodel.IdentityProfileBinding{
		WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey, ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID,
		IdentityUserID: desiredUserID, Status: status, InvitationChannel: mutation.InvitationChannel, ClaimProofType: mutation.ClaimProofType,
		Version: currentVersion + 1, CreatedAt: createdAt, UpdatedAt: now,
	}
	if mutation.Operation != identitymodel.IdentityProfileBindingInvite && !mutation.ProfileRecordStaged {
		if err := s.updateProfileIdentityUser(ctx, executor, mutation, currentUserID, desiredUserID, now); err != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, err
		}
	}
	if err := s.writeBinding(ctx, executor, next, found); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	if err := s.synchronizeSystemManagedRoles(ctx, executor, mutation, currentUserID, desiredUserID, now); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	receipt := identitymodel.IdentityProfileBindingReceipt{
		ID:          profileBindingStableID("receipt", mutation.WorkspaceID, mutation.ObjectKey, mutation.ProfileID, string(mutation.Operation), mutation.IdempotencyKey),
		WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey, ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID,
		Operation: mutation.Operation, IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint,
		Binding: next, CreatedAt: now,
	}
	if err := s.writeReceipt(ctx, executor, receipt, mutation); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	event := identitymodel.IdentityProfileBindingEvent{
		ID: profileBindingStableID("event", receipt.ID), OperationID: receipt.ID, CausationID: mutation.CausationID, WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey,
		ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID, Operation: mutation.Operation,
		PreviousUserID: currentUserID, IdentityUserID: desiredUserID, BindingVersion: next.Version,
		IdempotencyKey: mutation.IdempotencyKey, ActorID: mutation.ActorID, Reason: mutation.Reason, Status: "pending", CreatedAt: now,
		ApprovalID: mutation.ApprovalID,
	}
	if err := s.writeEvent(ctx, executor, event); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	return receipt, nil
}

func (s *Store) synchronizeSystemManagedRoles(ctx context.Context, executor identitytransaction.Executor, mutation identitymodel.IdentityProfileBindingMutation, previousUserID, nextUserID, now string) error {
	roleIDs := uniqueProfileBindingStrings(mutation.SystemManagedRoleIDs)
	if len(roleIDs) == 0 || mutation.Operation == identitymodel.IdentityProfileBindingInvite {
		return nil
	}
	if previousUserID != "" && (mutation.Operation == identitymodel.IdentityProfileBindingRebind || mutation.Operation == identitymodel.IdentityProfileBindingUnlink) {
		statement, arguments, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_user_role_assignments", mutation.WorkspaceID).
			Set("status", "revoked").Set("revoked_by", mutation.ActorID).Set("revoked_at", timevalue.Millis(now)).
			Set("revoke_reason", string(mutation.Operation)).Set("updated_at", timevalue.Millis(now)).
			Where(query.And(query.Equal("user_id", previousUserID), query.Equal("binding_key", mutation.BindingKey), query.Equal("profile_id", mutation.ProfileID), query.Equal("source", "profile_binding"))).Build()
		if buildErr != nil {
			return buildErr
		}
		if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	if nextUserID == "" {
		return nil
	}
	for _, roleID := range roleIDs {
		insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_user_role_assignments", mutation.WorkspaceID).
			Columns("id", "user_id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
			Values(profileBindingStableID("profile_role", mutation.WorkspaceID, nextUserID, roleID), nextUserID, roleID, mutation.BindingKey, mutation.ProfileID, "profile_binding", "active", int64(0), int64(0), mutation.ActorID, string(mutation.Operation), nil, int64(0), nil, int64(0), timevalue.Millis(now), timevalue.Millis(now))
		s.store.ApplyUpsert(insert, []string{"workspace_id", "id"}, "binding_key", "profile_id", "source", "status", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "updated_at")
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return buildErr
		}
		if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SynchronizeSystemManagedRoles(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, previousUserID, nextUserID, now string) error {
	return s.synchronizeSystemManagedRoles(ctx, tx, mutation, previousUserID, nextUserID, now)
}

func uniqueProfileBindingStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (s *Store) ListIdentityProfileBindingEvents(ctx context.Context, workspaceID, objectKey, profileID string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	binding := s.store.Audit()
	if binding == nil || binding.Reader() == nil {
		return nil, fmt.Errorf("Audit module binding is unavailable")
	}
	auditEvents, err := binding.Reader().List(ctx, strings.TrimSpace(workspaceID), auditcontract.Query{
		ObjectKey: strings.TrimSpace(objectKey), RecordID: strings.TrimSpace(profileID), Limit: 1000,
	})
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(profileBindingAuditEventNames()))
	for _, eventName := range profileBindingAuditEventNames() {
		allowed[eventName] = true
	}
	out := []identitymodel.IdentityProfileBindingEvent{}
	for _, auditEvent := range auditEvents {
		if !allowed[auditEvent.Event] {
			continue
		}
		var event identitymodel.IdentityProfileBindingEvent
		storedCreatedAt, ok := auditEvent.Metadata["created_at"].(float64)
		if !ok || storedCreatedAt != float64(timevalue.Millis(auditEvent.CreatedAt)) {
			return nil, fmt.Errorf("identity profile binding audit event scope mismatch")
		}
		metadata := make(map[string]any, len(auditEvent.Metadata))
		for key, value := range auditEvent.Metadata {
			metadata[key] = value
		}
		metadata["created_at"] = auditEvent.CreatedAt
		metadataJSON, marshalErr := json.Marshal(metadata)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if err := json.Unmarshal(metadataJSON, &event); err != nil {
			return nil, fmt.Errorf("decode Identity profile binding audit event: %w", err)
		}
		event.OperationID, event.CausationID = auditEvent.OperationID, auditEvent.CausationID
		if event.ID != auditEvent.ID || event.WorkspaceID != workspaceID || event.ObjectKey != strings.TrimSpace(objectKey) || event.ProfileID != strings.TrimSpace(profileID) ||
			profileBindingAuditPrefix+string(event.Operation) != auditEvent.Event || event.CreatedAt != auditEvent.CreatedAt {
			return nil, fmt.Errorf("identity profile binding audit event scope mismatch")
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out, nil
}

type identityProfileBindingQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) queryer(ctx context.Context) identityProfileBindingQuerier {
	if executor := identitytransaction.ExecutorFromContext(ctx); executor != nil {
		return executor
	}
	return s.store.DB()
}

func (s *Store) loadReceipt(ctx context.Context, queryer identityProfileBindingQuerier, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	operation, found, err := operationreceipt.Load(ctx, queryer, s.store.SQLRenderer(), mutation.WorkspaceID, profileBindingOperationOwner, profileBindingOperationKind, mutation.IdempotencyKey)
	if err != nil || !found {
		return identitymodel.IdentityProfileBindingReceipt{}, found, err
	}
	var receipt identitymodel.IdentityProfileBindingReceipt
	if err := json.Unmarshal(operation.ResultJSON, &receipt); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, err
	}
	if receipt.ID != operation.ID || receipt.WorkspaceID != mutation.WorkspaceID || receipt.BindingKey != mutation.BindingKey ||
		receipt.ObjectKey != mutation.ObjectKey || receipt.ProfileID != mutation.ProfileID || receipt.Operation != mutation.Operation ||
		receipt.IdempotencyKey != mutation.IdempotencyKey || operation.ResourceID != mutation.ProfileID {
		return identitymodel.IdentityProfileBindingReceipt{}, false, errors.New("identity shared profile binding operation scope mismatch")
	}
	receipt.RequestFingerprint = operation.RequestFingerprint
	receipt.CreatedAt = operation.CreatedAt
	return receipt, true, nil
}

func (s *Store) loadProfileIdentityUser(ctx context.Context, executor identityProfileBindingQuerier, mutation identitymodel.IdentityProfileBindingMutation) (string, error) {
	statement, arguments, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), mutation.ObjectKey, mutation.WorkspaceID).
		Projections(query.Project(query.Coalesce(query.Column(mutation.IdentityField), query.Value("")))).
		Where(query.Equal("id", mutation.ProfileID)).Build()
	if buildErr != nil {
		return "", buildErr
	}
	var userID string
	err := executor.QueryRowContext(ctx, statement, arguments...).Scan(&userID)
	return strings.TrimSpace(userID), err
}

func (s *Store) loadBinding(ctx context.Context, queryer identityProfileBindingQuerier, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	statement, arguments, buildErr := profileBindingSelect(s.store, workspaceID).
		Where(query.And(query.Equal("object_key", objectKey), query.Equal("profile_id", profileID))).Build()
	if buildErr != nil {
		return identitymodel.IdentityProfileBinding{}, false, buildErr
	}
	binding, err := scanIdentityProfileBinding(queryer.QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *Store) updateProfileIdentityUser(ctx context.Context, executor identitytransaction.Executor, mutation identitymodel.IdentityProfileBindingMutation, currentUserID, desiredUserID, now string) error {
	statement, arguments, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), mutation.ObjectKey, mutation.WorkspaceID).
		Set(mutation.IdentityField, nullableProfileBindingUser(desiredUserID)).Set("updated_at", timevalue.Millis(now)).
		Where(query.And(query.Equal("id", mutation.ProfileID), query.EqualExpressions(query.Coalesce(query.Column(mutation.IdentityField), query.Value("")), query.Value(currentUserID)))).Build()
	if buildErr != nil {
		return buildErr
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return normalizeProfileBindingWriteError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_binding_concurrent_mutation")
	}
	return nil
}

func (s *Store) UpdateProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, currentUserID, desiredUserID, now string) error {
	return s.updateProfileIdentityUser(ctx, tx, mutation, currentUserID, desiredUserID, now)
}

func (s *Store) writeBinding(ctx context.Context, executor identitytransaction.Executor, binding identitymodel.IdentityProfileBinding, found bool) error {
	if found {
		statement, arguments, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_profile_bindings", binding.WorkspaceID).
			Set("binding_key", binding.BindingKey).Set("identity_user_id", nullableProfileBindingUser(binding.IdentityUserID)).
			Set("status", string(binding.Status)).Set("invitation_channel", nullableProfileBindingText(binding.InvitationChannel)).
			Set("claim_proof_type", nullableProfileBindingText(binding.ClaimProofType)).Set("version", binding.Version).Set("updated_at", timevalue.Millis(binding.UpdatedAt)).
			Where(query.And(query.Equal("object_key", binding.ObjectKey), query.Equal("profile_id", binding.ProfileID))).Build()
		if buildErr != nil {
			return buildErr
		}
		_, err := executor.ExecContext(ctx, statement, arguments...)
		return err
	}
	statement, arguments, buildErr := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_profile_bindings", binding.WorkspaceID).
		Columns("id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at").
		Values(profileBindingStableID("binding", binding.WorkspaceID, binding.ObjectKey, binding.ProfileID), binding.BindingKey, binding.ObjectKey, binding.ProfileID, nullableProfileBindingUser(binding.IdentityUserID), string(binding.Status), nullableProfileBindingText(binding.InvitationChannel), nullableProfileBindingText(binding.ClaimProofType), binding.Version, timevalue.Millis(binding.CreatedAt), timevalue.Millis(binding.UpdatedAt)).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := executor.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) writeReceipt(ctx context.Context, executor identitytransaction.Executor, receipt identitymodel.IdentityProfileBindingReceipt, mutation identitymodel.IdentityProfileBindingMutation) error {
	resultJSON, _ := json.Marshal(receipt)
	relatedIDsJSON, _ := json.Marshal(uniqueProfileBindingStrings(append(
		[]string{receipt.ProfileID, receipt.Binding.IdentityUserID, mutation.ApprovalID}, mutation.SystemManagedRoleIDs...,
	)))
	reason := strings.TrimSpace(mutation.Reason)
	if reason == "" {
		reason = "execute identity profile binding " + string(receipt.Operation)
	}
	return operationreceipt.InsertSucceeded(ctx, executor, s.store.SQLRenderer(), operationreceipt.Succeeded{
		ID: receipt.ID, WorkspaceID: receipt.WorkspaceID, Owner: profileBindingOperationOwner, Kind: profileBindingOperationKind,
		ActionKey: "identity.profile_bindings.command", ResourceType: receipt.ObjectKey, ResourceID: receipt.ProfileID,
		IdempotencyKey: receipt.IdempotencyKey, RequestFingerprint: receipt.RequestFingerprint, RequestedBy: mutation.ActorID,
		Reason: reason, Reference: mutation.ApprovalID, ResultJSON: resultJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: receipt.CreatedAt,
	})
}

func (s *Store) writeEvent(ctx context.Context, executor identitytransaction.Executor, event identitymodel.IdentityProfileBindingEvent) error {
	metadataJSON, buildErr := json.Marshal(event)
	if buildErr != nil {
		return buildErr
	}
	metadata := map[string]any{}
	if buildErr = json.Unmarshal(metadataJSON, &metadata); buildErr != nil {
		return buildErr
	}
	prepared := auditcontract.Event{
		ID: event.ID, WorkspaceID: event.WorkspaceID, Family: auditcontract.EventFamilyIdentityProfileBinding,
		OperationID: event.OperationID, CausationID: event.CausationID, Event: profileBindingAuditPrefix + string(event.Operation),
		ObjectKey: event.ObjectKey, RecordID: event.ProfileID, ActorID: event.ActorID,
		Summary: "Identity profile binding " + string(event.Operation), Metadata: metadata, CreatedAt: event.CreatedAt,
	}
	if buildErr = auditcontract.ValidatePreparedEvent(prepared); buildErr != nil {
		return buildErr
	}
	binding := s.store.Audit()
	if binding == nil || binding.PreparedAppender() == nil {
		return fmt.Errorf("Audit module binding is unavailable")
	}
	return binding.PreparedAppender().AppendPreparedWithin(ctx, profileBindingAuditTransaction{executor: executor}, prepared)
}

type profileBindingAuditTransaction struct{ executor identitytransaction.Executor }

func (adapter profileBindingAuditTransaction) ExecContext(ctx context.Context, queryValue string, arguments ...any) (auditcontract.Result, error) {
	return adapter.executor.ExecContext(ctx, queryValue, arguments...)
}

func (adapter profileBindingAuditTransaction) QueryRowContext(ctx context.Context, queryValue string, arguments ...any) auditcontract.Row {
	return adapter.executor.QueryRowContext(ctx, queryValue, arguments...)
}

func profileBindingAuditEventNames() []string {
	return []string{
		profileBindingAuditPrefix + string(identitymodel.IdentityProfileBindingInvite),
		profileBindingAuditPrefix + string(identitymodel.IdentityProfileBindingClaim),
		profileBindingAuditPrefix + string(identitymodel.IdentityProfileBindingBind),
		profileBindingAuditPrefix + string(identitymodel.IdentityProfileBindingRebind),
		profileBindingAuditPrefix + string(identitymodel.IdentityProfileBindingUnlink),
	}
}

func scanIdentityProfileBinding(row interface{ Scan(...any) error }) (identitymodel.IdentityProfileBinding, error) {
	var binding identitymodel.IdentityProfileBinding
	var status string
	var identityUserID, invitationChannel, claimProofType sql.NullString
	var createdAt, updatedAt int64
	err := row.Scan(&binding.WorkspaceID, &binding.BindingKey, &binding.ObjectKey, &binding.ProfileID, &identityUserID, &status, &invitationChannel, &claimProofType, &binding.Version, &createdAt, &updatedAt)
	binding.IdentityUserID = identityUserID.String
	binding.InvitationChannel = invitationChannel.String
	binding.ClaimProofType = claimProofType.String
	binding.Status = identitymodel.IdentityProfileBindingStatus(status)
	binding.CreatedAt, binding.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
	return binding, err
}

func Scan(row interface{ Scan(...any) error }) (identitymodel.IdentityProfileBinding, error) {
	return scanIdentityProfileBinding(row)
}

func identityProfileBindingTransition(mutation identitymodel.IdentityProfileBindingMutation, currentUserID string) (identitymodel.IdentityProfileBindingStatus, string, error) {
	switch mutation.Operation {
	case identitymodel.IdentityProfileBindingInvite:
		if currentUserID != "" {
			return "", "", profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_already_bound")
		}
		return identitymodel.IdentityProfileBindingInvited, "", nil
	case identitymodel.IdentityProfileBindingClaim, identitymodel.IdentityProfileBindingBind:
		if currentUserID != "" {
			return "", "", profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_already_bound")
		}
		if mutation.IdentityUserID == "" {
			return "", "", profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_target_invalid")
		}
		return identitymodel.IdentityProfileBindingActive, mutation.IdentityUserID, nil
	case identitymodel.IdentityProfileBindingRebind:
		if currentUserID == "" || mutation.IdentityUserID == "" || mutation.Reason == "" {
			return "", "", profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_rebind_invalid")
		}
		if currentUserID == mutation.IdentityUserID {
			return "", "", profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_binding_unchanged")
		}
		return identitymodel.IdentityProfileBindingActive, mutation.IdentityUserID, nil
	case identitymodel.IdentityProfileBindingUnlink:
		if currentUserID == "" {
			return "", "", profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_not_bound")
		}
		return identitymodel.IdentityProfileBindingUnlinked, "", nil
	default:
		return "", "", profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_operation_invalid")
	}
}

func Transition(mutation identitymodel.IdentityProfileBindingMutation, currentUserID string) (identitymodel.IdentityProfileBindingStatus, string, error) {
	return identityProfileBindingTransition(mutation, currentUserID)
}

func validateIdentityProfileBindingMutation(mutation identitymodel.IdentityProfileBindingMutation) error {
	if _, err := identitymodel.NewWorkspaceID(mutation.WorkspaceID); err != nil {
		return profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_command_invalid")
	}
	if strings.TrimSpace(mutation.BindingKey) == "" || strings.TrimSpace(mutation.ObjectKey) == "" ||
		strings.TrimSpace(mutation.ProfileID) == "" || strings.TrimSpace(mutation.IdentityField) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" ||
		strings.TrimSpace(mutation.RequestFingerprint) == "" || strings.TrimSpace(mutation.ActorID) == "" || mutation.ExpectedVersion < 0 {
		return profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_command_invalid")
	}
	if mutation.ProfileRecordStaged && (mutation.Operation != identitymodel.IdentityProfileBindingBind || mutation.ExpectedVersion != 0 || strings.TrimSpace(mutation.IdentityUserID) == "") {
		return profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_staged_create_invalid")
	}
	return nil
}

func ValidateMutation(mutation identitymodel.IdentityProfileBindingMutation) error {
	return validateIdentityProfileBindingMutation(mutation)
}

func profileBindingStableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func profileBindingNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func nullableProfileBindingUser(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func nullableProfileBindingText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func normalizeProfileBindingWriteError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		return profileBindingStoreError(apperror.KindConflict, "backend.identity.profile_binding_conflict")
	}
	return err
}

func NormalizeWriteError(err error) error { return normalizeProfileBindingWriteError(err) }

func profileBindingStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
