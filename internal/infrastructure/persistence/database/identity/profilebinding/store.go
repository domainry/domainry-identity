package profilebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
}

func (s *Store) ListIdentityProfileBindingsByUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	statement, arguments, err := profileBindingSelect(s.store, workspaceID).
		Where(ormbuilder.Equal("identity_user_id", strings.TrimSpace(userID))).
		OrderBy(ormbuilder.Ascending("object_key"), ormbuilder.Ascending("profile_id")).
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
		Where(ormbuilder.And(ormbuilder.Equal("object_key", objectKey), ormbuilder.Equal("profile_id", profileID))).Build()
	if err != nil {
		return identitymodel.IdentityProfileBinding{}, false, err
	}
	binding, err := scanIdentityProfileBinding(s.store.DB().QueryRowContext(ctx, statement, arguments...))
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
		Where(ormbuilder.And(ormbuilder.Equal("binding_key", bindingKey), ormbuilder.Equal("profile_id", profileID))).Build()
	if err != nil {
		return identitymodel.IdentityProfileBinding{}, false, err
	}
	binding, err := scanIdentityProfileBinding(s.store.DB().QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func profileBindingSelect(store Backend, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(store.SQLRenderer(), "identity_profile_bindings", workspaceID).
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
	return s.loadReceipt(ctx, s.store.DB(), mutation)
}

func (s *Store) ExecuteIdentityProfileBindingMutation(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	if err := validateIdentityProfileBindingMutation(mutation); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadReceipt(ctx, tx, mutation); loadErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Replayed = true
		return receipt, nil
	}
	currentUserID, err := s.loadProfileIdentityUser(ctx, tx, mutation)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingStoreError(apperror.KindNotFound, "backend.identity.profile_not_found")
	}
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	current, found, err := s.loadBinding(ctx, tx, mutation.WorkspaceID, mutation.ObjectKey, mutation.ProfileID)
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
	// A legacy/business seed may have materialized the exact user/profile
	// relation before the authoritative binding ledger existed. Adopt only
	// that identical fact when no ledger row exists; a different target, an
	// existing ledger, or every other operation keeps the normal conflict
	// semantics. This makes manifest convergence idempotent without weakening
	// rebind ownership or optimistic version checks.
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
	if mutation.Operation != identitymodel.IdentityProfileBindingInvite {
		if err := s.updateProfileIdentityUser(ctx, tx, mutation, currentUserID, desiredUserID, now); err != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, err
		}
	}
	if err := s.writeBinding(ctx, tx, next, found); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	if err := s.synchronizeSystemManagedRoles(ctx, tx, mutation, currentUserID, desiredUserID, now); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	receipt := identitymodel.IdentityProfileBindingReceipt{
		ID:          profileBindingStableID("receipt", mutation.WorkspaceID, mutation.ObjectKey, mutation.ProfileID, string(mutation.Operation), mutation.IdempotencyKey),
		WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey, ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID,
		Operation: mutation.Operation, IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint,
		Binding: next, CreatedAt: now,
	}
	if err := s.writeReceipt(ctx, tx, receipt); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	event := identitymodel.IdentityProfileBindingEvent{
		ID: profileBindingStableID("event", receipt.ID), WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey,
		ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID, Operation: mutation.Operation,
		PreviousUserID: currentUserID, IdentityUserID: desiredUserID, BindingVersion: next.Version,
		IdempotencyKey: mutation.IdempotencyKey, ActorID: mutation.ActorID, Reason: mutation.Reason, Status: "pending", CreatedAt: now,
		ApprovalID: mutation.ApprovalID,
	}
	if err := s.writeEvent(ctx, tx, event); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, normalizeProfileBindingWriteError(err)
	}
	return receipt, nil
}

func (s *Store) synchronizeSystemManagedRoles(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, previousUserID, nextUserID, now string) error {
	roleIDs := uniqueProfileBindingStrings(mutation.SystemManagedRoleIDs)
	if len(roleIDs) == 0 || mutation.Operation == identitymodel.IdentityProfileBindingInvite {
		return nil
	}
	if previousUserID != "" && (mutation.Operation == identitymodel.IdentityProfileBindingRebind || mutation.Operation == identitymodel.IdentityProfileBindingUnlink) {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_user_role_assignments", mutation.WorkspaceID).
			Set("status", "revoked").Set("revoked_by", mutation.ActorID).Set("revoked_at", now).
			Set("revoke_reason", string(mutation.Operation)).Set("updated_at", now).
			Where(ormbuilder.And(ormbuilder.Equal("user_id", previousUserID), ormbuilder.Equal("binding_key", mutation.BindingKey), ormbuilder.Equal("profile_id", mutation.ProfileID), ormbuilder.Equal("source", "profile_binding"))).Build()
		if buildErr != nil {
			return buildErr
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	if nextUserID == "" {
		return nil
	}
	for _, roleID := range roleIDs {
		insert := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_user_role_assignments", mutation.WorkspaceID).
			Columns("id", "user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
			Values(profileBindingStableID("profile_role", mutation.WorkspaceID, nextUserID, roleID), nextUserID, roleID, nil, mutation.BindingKey, mutation.ProfileID, "profile_binding", "active", nil, nil, mutation.ActorID, string(mutation.Operation), nil, nil, nil, nil, now, now)
		s.store.ApplyUpsert(insert, []string{"workspace_id", "id"}, "binding_key", "profile_id", "source", "status", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "updated_at")
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return buildErr
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
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
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_profile_binding_events", workspaceID).
		Columns("id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "previous_user_id", "identity_user_id", "binding_version", "idempotency_key", "actor_id", "reason", "approval_id", "status", "created_at").
		Where(ormbuilder.And(ormbuilder.Equal("object_key", objectKey), ormbuilder.Equal("profile_id", profileID))).
		OrderBy(ormbuilder.Ascending("created_at"), ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.store.DB().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityProfileBindingEvent{}
	for rows.Next() {
		var event identitymodel.IdentityProfileBindingEvent
		var operation string
		var previousUserID, identityUserID, reason, approvalID sql.NullString
		if err := rows.Scan(&event.ID, &event.WorkspaceID, &event.BindingKey, &event.ObjectKey, &event.ProfileID, &operation, &previousUserID, &identityUserID, &event.BindingVersion, &event.IdempotencyKey, &event.ActorID, &reason, &approvalID, &event.Status, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Operation = identitymodel.IdentityProfileBindingOperation(operation)
		event.PreviousUserID = previousUserID.String
		event.IdentityUserID = identityUserID.String
		event.Reason = reason.String
		event.ApprovalID = approvalID.String
		out = append(out, event)
	}
	return out, rows.Err()
}

type identityProfileBindingQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) loadReceipt(ctx context.Context, queryer identityProfileBindingQuerier, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_profile_binding_receipts", mutation.WorkspaceID).
		Columns("id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at").
		Where(ormbuilder.And(ormbuilder.Equal("object_key", mutation.ObjectKey), ormbuilder.Equal("profile_id", mutation.ProfileID), ormbuilder.Equal("operation", string(mutation.Operation)), ormbuilder.Equal("idempotency_key", mutation.IdempotencyKey))).Build()
	if buildErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, buildErr
	}
	var receipt identitymodel.IdentityProfileBindingReceipt
	var operation, bindingJSON string
	err := queryer.QueryRowContext(ctx, statement, arguments...).
		Scan(&receipt.ID, &receipt.WorkspaceID, &receipt.BindingKey, &receipt.ObjectKey, &receipt.ProfileID, &operation, &receipt.IdempotencyKey, &receipt.RequestFingerprint, &bindingJSON, &receipt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBindingReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, err
	}
	receipt.Operation = identitymodel.IdentityProfileBindingOperation(operation)
	if err := json.Unmarshal([]byte(bindingJSON), &receipt.Binding); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s *Store) loadProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation) (string, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), mutation.ObjectKey, mutation.WorkspaceID).
		Projections(ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.Column(mutation.IdentityField), ormbuilder.Value("")))).
		Where(ormbuilder.Equal("id", mutation.ProfileID)).Build()
	if buildErr != nil {
		return "", buildErr
	}
	var userID string
	err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&userID)
	return strings.TrimSpace(userID), err
}

func (s *Store) loadBinding(ctx context.Context, queryer identityProfileBindingQuerier, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	statement, arguments, buildErr := profileBindingSelect(s.store, workspaceID).
		Where(ormbuilder.And(ormbuilder.Equal("object_key", objectKey), ormbuilder.Equal("profile_id", profileID))).Build()
	if buildErr != nil {
		return identitymodel.IdentityProfileBinding{}, false, buildErr
	}
	binding, err := scanIdentityProfileBinding(queryer.QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *Store) updateProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, currentUserID, desiredUserID, now string) error {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), mutation.ObjectKey, mutation.WorkspaceID).
		Set(mutation.IdentityField, nullableProfileBindingUser(desiredUserID)).Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("id", mutation.ProfileID), ormbuilder.EqualExpressions(ormbuilder.Coalesce(ormbuilder.Column(mutation.IdentityField), ormbuilder.Value("")), ormbuilder.Value(currentUserID)))).Build()
	if buildErr != nil {
		return buildErr
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
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

func (s *Store) writeBinding(ctx context.Context, tx *sql.Tx, binding identitymodel.IdentityProfileBinding, found bool) error {
	if found {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_profile_bindings", binding.WorkspaceID).
			Set("binding_key", binding.BindingKey).Set("identity_user_id", nullableProfileBindingUser(binding.IdentityUserID)).
			Set("status", string(binding.Status)).Set("invitation_channel", nullableProfileBindingText(binding.InvitationChannel)).
			Set("claim_proof_type", nullableProfileBindingText(binding.ClaimProofType)).Set("version", binding.Version).Set("updated_at", binding.UpdatedAt).
			Where(ormbuilder.And(ormbuilder.Equal("object_key", binding.ObjectKey), ormbuilder.Equal("profile_id", binding.ProfileID))).Build()
		if buildErr != nil {
			return buildErr
		}
		_, err := tx.ExecContext(ctx, statement, arguments...)
		return err
	}
	statement, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_profile_bindings", binding.WorkspaceID).
		Columns("id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at").
		Values(profileBindingStableID("binding", binding.WorkspaceID, binding.ObjectKey, binding.ProfileID), binding.BindingKey, binding.ObjectKey, binding.ProfileID, nullableProfileBindingUser(binding.IdentityUserID), string(binding.Status), nullableProfileBindingText(binding.InvitationChannel), nullableProfileBindingText(binding.ClaimProofType), binding.Version, binding.CreatedAt, binding.UpdatedAt).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := tx.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) writeReceipt(ctx context.Context, tx *sql.Tx, receipt identitymodel.IdentityProfileBindingReceipt) error {
	// This concrete binding contains only JSON-safe scalar fields.
	bindingJSON, _ := json.Marshal(receipt.Binding)
	statement, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_profile_binding_receipts", receipt.WorkspaceID).
		Columns("id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at").
		Values(receipt.ID, receipt.BindingKey, receipt.ObjectKey, receipt.ProfileID, string(receipt.Operation), receipt.IdempotencyKey, receipt.RequestFingerprint, string(bindingJSON), receipt.CreatedAt).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := tx.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) writeEvent(ctx context.Context, tx *sql.Tx, event identitymodel.IdentityProfileBindingEvent) error {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_profile_binding_events", event.WorkspaceID).
		Columns("id", "binding_key", "object_key", "profile_id", "operation", "previous_user_id", "identity_user_id", "binding_version", "idempotency_key", "actor_id", "reason", "approval_id", "status", "created_at").
		Values(event.ID, event.BindingKey, event.ObjectKey, event.ProfileID, string(event.Operation), nullableProfileBindingText(event.PreviousUserID), nullableProfileBindingText(event.IdentityUserID), event.BindingVersion, event.IdempotencyKey, event.ActorID, nullableProfileBindingText(event.Reason), nullableProfileBindingText(event.ApprovalID), event.Status, event.CreatedAt).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := tx.ExecContext(ctx, statement, arguments...)
	return err
}

func scanIdentityProfileBinding(row interface{ Scan(...any) error }) (identitymodel.IdentityProfileBinding, error) {
	var binding identitymodel.IdentityProfileBinding
	var status string
	var identityUserID, invitationChannel, claimProofType sql.NullString
	err := row.Scan(&binding.WorkspaceID, &binding.BindingKey, &binding.ObjectKey, &binding.ProfileID, &identityUserID, &status, &invitationChannel, &claimProofType, &binding.Version, &binding.CreatedAt, &binding.UpdatedAt)
	binding.IdentityUserID = identityUserID.String
	binding.InvitationChannel = invitationChannel.String
	binding.ClaimProofType = claimProofType.String
	binding.Status = identitymodel.IdentityProfileBindingStatus(status)
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
		strings.TrimSpace(mutation.RequestFingerprint) == "" || mutation.ExpectedVersion < 0 {
		return profileBindingStoreError(apperror.KindBadRequest, "backend.identity.profile_binding_command_invalid")
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
