package identity

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
)

type IdentityProfileBindingStore struct {
	store lifecycleSQLStore
}

func NewIdentityProfileBindingStore(store lifecycleSQLStore) *IdentityProfileBindingStore {
	return &IdentityProfileBindingStore{store: store}
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBinding(ctx context.Context, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	query := "SELECT " + joinProfileBindingColumns(s.store, "workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at") +
		" FROM " + s.store.TableIdentifier("identity_profile_bindings") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
		" AND " + s.store.Identifier("object_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(3)
	binding, err := scanIdentityProfileBinding(s.store.DB().QueryRowContext(ctx, query, workspaceID, objectKey, profileID))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBindingByKey(ctx context.Context, workspaceID, bindingKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	query := "SELECT " + joinProfileBindingColumns(s.store, "workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at") +
		" FROM " + s.store.TableIdentifier("identity_profile_bindings") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
		" AND " + s.store.Identifier("binding_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(3)
	binding, err := scanIdentityProfileBinding(s.store.DB().QueryRowContext(ctx, query, workspaceID, bindingKey, profileID))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *IdentityProfileBindingStore) IdentityRoleBindingActive(ctx context.Context, workspaceID, bindingKey, profileID, userID string) (bool, error) {
	binding, found, err := s.GetIdentityProfileBindingByKey(ctx, workspaceID, strings.TrimSpace(bindingKey), strings.TrimSpace(profileID))
	if err != nil || !found {
		return false, err
	}
	return binding.Status == identitymodel.IdentityProfileBindingActive && strings.TrimSpace(binding.IdentityUserID) == strings.TrimSpace(userID), nil
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBindingReceipt(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	if s == nil || s.store == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, profileBindingStoreError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	return s.loadReceipt(ctx, s.store.DB(), mutation)
}

func (s *IdentityProfileBindingStore) ExecuteIdentityProfileBindingMutation(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
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

func (s *IdentityProfileBindingStore) synchronizeSystemManagedRoles(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, previousUserID, nextUserID, now string) error {
	roleIDs := uniqueProfileBindingStrings(mutation.SystemManagedRoleIDs)
	if len(roleIDs) == 0 || mutation.Operation == identitymodel.IdentityProfileBindingInvite {
		return nil
	}
	if previousUserID != "" && (mutation.Operation == identitymodel.IdentityProfileBindingRebind || mutation.Operation == identitymodel.IdentityProfileBindingUnlink) {
		query := "UPDATE " + s.store.TableIdentifier("identity_user_role_assignments") + " SET " +
			s.store.Identifier("status") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("revoked_by") + " = " + s.store.Placeholder(2) + ", " +
			s.store.Identifier("revoked_at") + " = " + s.store.Placeholder(3) + ", " + s.store.Identifier("revoke_reason") + " = " + s.store.Placeholder(4) + ", " +
			s.store.Identifier("updated_at") + " = " + s.store.Placeholder(5) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(6) +
			" AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(7) + " AND " + s.store.Identifier("binding_key") + " = " + s.store.Placeholder(8) +
			" AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(9) + " AND " + s.store.Identifier("source") + " = " + s.store.Placeholder(10)
		if _, err := tx.ExecContext(ctx, query, "revoked", mutation.ActorID, now, string(mutation.Operation), now, mutation.WorkspaceID, previousUserID, mutation.BindingKey, mutation.ProfileID, "profile_binding"); err != nil {
			return err
		}
	}
	if nextUserID == "" {
		return nil
	}
	for _, roleID := range roleIDs {
		deleteQuery := "DELETE FROM " + s.store.TableIdentifier("identity_user_role_assignments") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
			" AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("role_id") + " = " + s.store.Placeholder(3)
		if _, err := tx.ExecContext(ctx, deleteQuery,
			mutation.WorkspaceID, nextUserID, roleID); err != nil {
			return err
		}
		columns := profileBindingColumnNames(s.store, "id", "workspace_id", "user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at")
		query := "INSERT INTO " + s.store.TableIdentifier("identity_user_role_assignments") + " (" + columns + ") VALUES (" + profileBindingPlaceholders(s.store, 19) + ")"
		if _, err := tx.ExecContext(ctx, query,
			profileBindingStableID("profile_role", mutation.WorkspaceID, nextUserID, roleID), mutation.WorkspaceID, nextUserID, roleID,
			nil, mutation.BindingKey, mutation.ProfileID, "profile_binding", "active", nil, nil, mutation.ActorID, string(mutation.Operation),
			nil, nil, nil, nil, now, now,
		); err != nil {
			return err
		}
	}
	return nil
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

func (s *IdentityProfileBindingStore) ListIdentityProfileBindingEvents(ctx context.Context, workspaceID, objectKey, profileID string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	query := "SELECT " + joinProfileBindingColumns(s.store, "id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "previous_user_id", "identity_user_id", "binding_version", "idempotency_key", "actor_id", "reason", "approval_id", "status", "created_at") +
		" FROM " + s.store.TableIdentifier("identity_profile_binding_events") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
		" AND " + s.store.Identifier("object_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(3) +
		" ORDER BY " + s.store.Identifier("created_at") + ", " + s.store.Identifier("id")
	rows, err := s.store.DB().QueryContext(ctx, query, workspaceID, objectKey, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityProfileBindingEvent{}
	for rows.Next() {
		var event identitymodel.IdentityProfileBindingEvent
		var operation string
		var approvalID sql.NullString
		if err := rows.Scan(&event.ID, &event.WorkspaceID, &event.BindingKey, &event.ObjectKey, &event.ProfileID, &operation, &event.PreviousUserID, &event.IdentityUserID, &event.BindingVersion, &event.IdempotencyKey, &event.ActorID, &event.Reason, &approvalID, &event.Status, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Operation = identitymodel.IdentityProfileBindingOperation(operation)
		event.ApprovalID = approvalID.String
		out = append(out, event)
	}
	return out, rows.Err()
}

type identityProfileBindingQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *IdentityProfileBindingStore) loadReceipt(ctx context.Context, queryer identityProfileBindingQuerier, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	query := "SELECT " + joinProfileBindingColumns(s.store, "id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at") +
		" FROM " + s.store.TableIdentifier("identity_profile_binding_receipts") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
		" AND " + s.store.Identifier("object_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(3) +
		" AND " + s.store.Identifier("operation") + " = " + s.store.Placeholder(4) + " AND " + s.store.Identifier("idempotency_key") + " = " + s.store.Placeholder(5)
	var receipt identitymodel.IdentityProfileBindingReceipt
	var operation, bindingJSON string
	err := queryer.QueryRowContext(ctx, query, mutation.WorkspaceID, mutation.ObjectKey, mutation.ProfileID, string(mutation.Operation), mutation.IdempotencyKey).
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

func (s *IdentityProfileBindingStore) loadProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation) (string, error) {
	query := "SELECT COALESCE(" + s.store.Identifier(mutation.IdentityField) + ", '') FROM " + s.store.TableIdentifier(mutation.ObjectKey) +
		" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(2)
	var userID string
	err := tx.QueryRowContext(ctx, query, mutation.WorkspaceID, mutation.ProfileID).Scan(&userID)
	return strings.TrimSpace(userID), err
}

func (s *IdentityProfileBindingStore) loadBinding(ctx context.Context, queryer identityProfileBindingQuerier, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	query := "SELECT " + joinProfileBindingColumns(s.store, "workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at") +
		" FROM " + s.store.TableIdentifier("identity_profile_bindings") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
		" AND " + s.store.Identifier("object_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(3)
	binding, err := scanIdentityProfileBinding(queryer.QueryRowContext(ctx, query, workspaceID, objectKey, profileID))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityProfileBinding{}, false, nil
	}
	return binding, err == nil, err
}

func (s *IdentityProfileBindingStore) updateProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, currentUserID, desiredUserID, now string) error {
	query := "UPDATE " + s.store.TableIdentifier(mutation.ObjectKey) + " SET " + s.store.Identifier(mutation.IdentityField) + " = " + s.store.Placeholder(1) +
		", " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(2) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(3) +
		" AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(4) + " AND COALESCE(" + s.store.Identifier(mutation.IdentityField) + ", '') = " + s.store.Placeholder(5)
	result, err := tx.ExecContext(ctx, query, nullableProfileBindingUser(desiredUserID), now, mutation.WorkspaceID, mutation.ProfileID, currentUserID)
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

func (s *IdentityProfileBindingStore) writeBinding(ctx context.Context, tx *sql.Tx, binding identitymodel.IdentityProfileBinding, found bool) error {
	if found {
		query := "UPDATE " + s.store.TableIdentifier("identity_profile_bindings") + " SET " +
			s.store.Identifier("binding_key") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("identity_user_id") + " = " + s.store.Placeholder(2) + ", " +
			s.store.Identifier("status") + " = " + s.store.Placeholder(3) + ", " + s.store.Identifier("invitation_channel") + " = " + s.store.Placeholder(4) + ", " +
			s.store.Identifier("claim_proof_type") + " = " + s.store.Placeholder(5) + ", " + s.store.Identifier("version") + " = " + s.store.Placeholder(6) + ", " +
			s.store.Identifier("updated_at") + " = " + s.store.Placeholder(7) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(8) +
			" AND " + s.store.Identifier("object_key") + " = " + s.store.Placeholder(9) + " AND " + s.store.Identifier("profile_id") + " = " + s.store.Placeholder(10)
		_, err := tx.ExecContext(ctx, query, binding.BindingKey, nullableProfileBindingUser(binding.IdentityUserID), string(binding.Status), nullableProfileBindingText(binding.InvitationChannel), nullableProfileBindingText(binding.ClaimProofType), binding.Version, binding.UpdatedAt, binding.WorkspaceID, binding.ObjectKey, binding.ProfileID)
		return err
	}
	columns := profileBindingColumnNames(s.store, "id", "workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at")
	query := "INSERT INTO " + s.store.TableIdentifier("identity_profile_bindings") + " (" + columns + ") VALUES (" + profileBindingPlaceholders(s.store, 12) + ")"
	_, err := tx.ExecContext(ctx, query, profileBindingStableID("binding", binding.WorkspaceID, binding.ObjectKey, binding.ProfileID), binding.WorkspaceID, binding.BindingKey, binding.ObjectKey, binding.ProfileID, nullableProfileBindingUser(binding.IdentityUserID), string(binding.Status), nullableProfileBindingText(binding.InvitationChannel), nullableProfileBindingText(binding.ClaimProofType), binding.Version, binding.CreatedAt, binding.UpdatedAt)
	return err
}

func (s *IdentityProfileBindingStore) writeReceipt(ctx context.Context, tx *sql.Tx, receipt identitymodel.IdentityProfileBindingReceipt) error {
	// This concrete binding contains only JSON-safe scalar fields.
	bindingJSON, _ := json.Marshal(receipt.Binding)
	columns := profileBindingColumnNames(s.store, "id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at")
	query := "INSERT INTO " + s.store.TableIdentifier("identity_profile_binding_receipts") + " (" + columns + ") VALUES (" + profileBindingPlaceholders(s.store, 10) + ")"
	_, err := tx.ExecContext(ctx, query, receipt.ID, receipt.WorkspaceID, receipt.BindingKey, receipt.ObjectKey, receipt.ProfileID, string(receipt.Operation), receipt.IdempotencyKey, receipt.RequestFingerprint, string(bindingJSON), receipt.CreatedAt)
	return err
}

func (s *IdentityProfileBindingStore) writeEvent(ctx context.Context, tx *sql.Tx, event identitymodel.IdentityProfileBindingEvent) error {
	columns := profileBindingColumnNames(s.store, "id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "previous_user_id", "identity_user_id", "binding_version", "idempotency_key", "actor_id", "reason", "approval_id", "status", "created_at")
	query := "INSERT INTO " + s.store.TableIdentifier("identity_profile_binding_events") + " (" + columns + ") VALUES (" + profileBindingPlaceholders(s.store, 15) + ")"
	_, err := tx.ExecContext(ctx, query, event.ID, event.WorkspaceID, event.BindingKey, event.ObjectKey, event.ProfileID, string(event.Operation), nullableProfileBindingText(event.PreviousUserID), nullableProfileBindingText(event.IdentityUserID), event.BindingVersion, event.IdempotencyKey, event.ActorID, nullableProfileBindingText(event.Reason), nullableProfileBindingText(event.ApprovalID), event.Status, event.CreatedAt)
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

func joinProfileBindingColumns(store lifecycleSQLStore, columns ...string) string {
	out := make([]string, 0, len(columns))
	for _, column := range columns {
		if column == "identity_user_id" || column == "invitation_channel" || column == "claim_proof_type" || column == "previous_user_id" || column == "reason" {
			out = append(out, "COALESCE("+store.Identifier(column)+", '')")
		} else {
			out = append(out, store.Identifier(column))
		}
	}
	return strings.Join(out, ", ")
}

func profileBindingColumnNames(store lifecycleSQLStore, columns ...string) string {
	out := make([]string, 0, len(columns))
	for _, column := range columns {
		out = append(out, store.Identifier(column))
	}
	return strings.Join(out, ", ")
}

func profileBindingPlaceholders(store lifecycleSQLStore, count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = store.Placeholder(index + 1)
	}
	return strings.Join(values, ", ")
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

func profileBindingStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
