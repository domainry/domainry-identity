package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s *SQLIdentityStore) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	return s.loadRoles(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityRole(ctx context.Context, workspaceID string, role identitymodel.IdentityRole) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if role.ID == "" {
		return fmt.Errorf("role id is required")
	}
	if role.Key == "" {
		role.Key = role.ID
	}
	if role.Status == "" {
		role.Status = identitymodel.IdentityStatusActive
	}
	now := nowString()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_roles", workspaceID).
		Columns("id", "role_key", "label", "description", "status", "created_at", "updated_at").
		Values(role.ID, role.Key, role.Label, role.Description, string(role.Status), now, now)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "role_key", "label", "description", "status", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity role upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) RemoveIdentityRole(ctx context.Context, workspaceID, roleID string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	for _, table := range []string{
		"identity_user_role_assignments",
		"identity_role_menu_assignments",
	} {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), table, workspaceID).Where(ormbuilder.Equal("role_id", roleID)).Build()
		if buildErr != nil {
			return fmt.Errorf("build identity role relation delete: %w", buildErr)
		}
		if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_roles", workspaceID).Where(ormbuilder.Equal("id", roleID)).Build()
	if err != nil {
		return fmt.Errorf("build identity role delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) AssignIdentityUserRole(ctx context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.writeIdentityUserRoleAssignment(ctx, s.db, workspaceID, assignment)
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignment(ctx context.Context, execer identityUserExecer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return roleassignmentpersistence.New(s, nowString).Upsert(ctx, execer, workspaceID, assignment)
}

func (s *SQLIdentityStore) RemoveIdentityUserRole(ctx context.Context, workspaceID, userID string, roleID string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_user_role_assignments", workspaceID).
		Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("role_id", roleID))).Build()
	if err != nil {
		return fmt.Errorf("build identity user-role assignment delete: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.loadUserRoleAssignments(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) CreateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if request.ID == "" || request.UserID == "" || len(request.RoleIDs) == 0 {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("role request id, user id, and roles are required")
	}
	now := nowString()
	if request.CreatedAt == "" {
		request.CreatedAt = now
	}
	request.UpdatedAt = now
	if request.Status == "" {
		request.Status = "pending"
	}
	roleIDsJSON, _ := json.Marshal(uniqueSortedStrings(request.RoleIDs))
	statement, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_role_requests", workspaceID).
		Columns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note").
		Values(request.ID, request.UserID, nullableText(request.RequestedBy), nullableText(request.Provider), nullableText(request.ProviderSubject), string(roleIDsJSON), request.Status, nullableText(request.Reason), request.CreatedAt, request.UpdatedAt, nullableText(request.ReviewedBy), nullableText(request.ReviewedAt), nullableText(request.ReviewNote)).
		Build()
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("build identity role request insert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return request, nil
}

func (s *SQLIdentityStore) ListIdentityRoleRequests(ctx context.Context, workspaceID, status string, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.loadRoleRequests(ctx, workspaceID, status, userID)
}

func (s *SQLIdentityStore) UpdateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if request.ID == "" {
		return fmt.Errorf("role request id is required")
	}
	if request.UpdatedAt == "" {
		request.UpdatedAt = nowString()
	}
	roleIDsJSON, _ := json.Marshal(uniqueSortedStrings(request.RoleIDs))
	statement, arguments, err := roleRequestUpdate(s, workspaceID, request, string(roleIDsJSON)).Build()
	if err != nil {
		return fmt.Errorf("build identity role request update: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) ApplyIdentityRoleRequestDecision(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, assignment := range assignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return err
		}
	}
	roleIDsJSON, _ := json.Marshal(uniqueSortedStrings(request.RoleIDs))
	statement, arguments, err := roleRequestUpdate(s, workspaceID, request, string(roleIDsJSON)).
		Where(ormbuilder.And(ormbuilder.Equal("id", request.ID), ormbuilder.Equal("status", expectedStatus))).
		Build()
	if err != nil {
		return fmt.Errorf("build identity role request decision: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	return tx.Commit()
}

func roleRequestUpdate(s *SQLIdentityStore, workspaceID string, request identitymodel.IdentityRoleRequest, roleIDsJSON string) *ormbuilder.UpdateBuilder {
	return ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_role_requests", workspaceID).
		Set("role_ids_json", roleIDsJSON).
		Set("status", request.Status).
		Set("reason", nullableText(request.Reason)).
		Set("updated_at", request.UpdatedAt).
		Set("reviewed_by", nullableText(request.ReviewedBy)).
		Set("reviewed_at", nullableText(request.ReviewedAt)).
		Set("review_note", nullableText(request.ReviewNote)).
		Where(ormbuilder.Equal("id", request.ID))
}

func (s *SQLIdentityStore) loadRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_roles", workspaceID).
		Columns("id", "role_key", "label", "description", "status").OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role list: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRole{}
	for rows.Next() {
		var role identitymodel.IdentityRole
		var status string
		if err := rows.Scan(&role.ID, &role.Key, &role.Label, &role.Description, &status); err != nil {
			return nil, err
		}
		role.Status = identitymodel.IdentityStatus(status)
		out = append(out, role)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) loadUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_user_role_assignments", workspaceID).
		Columns("user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
		OrderBy(ormbuilder.Ascending("user_id"), ormbuilder.Ascending("role_id"))
	if strings.TrimSpace(userID) != "" {
		builder.Where(ormbuilder.Equal("user_id", userID))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity user-role assignment list: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityUserRoleAssignment{}
	for rows.Next() {
		var assignment identitymodel.IdentityUserRoleAssignment
		var workforceProfileID, bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
		if err := rows.Scan(&assignment.UserID, &assignment.RoleID, &workforceProfileID, &bindingKey, &profileID, &assignment.Source, &assignment.Status, &validFrom, &validUntil, &grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &assignment.CreatedAt, &assignment.UpdatedAt); err != nil {
			return nil, err
		}
		assignment.WorkforceProfileID = workforceProfileID.String
		assignment.BindingKey = bindingKey.String
		assignment.ProfileID = profileID.String
		assignment.ValidFrom = validFrom.String
		assignment.ValidUntil = validUntil.String
		assignment.GrantedBy = grantedBy.String
		assignment.GrantReason = grantReason.String
		assignment.RevokedBy = revokedBy.String
		assignment.RevokedAt = revokedAt.String
		assignment.RevokeReason = revokeReason.String
		assignment.ExpiresAt = pointerFromNull(expiresAt)
		out = append(out, assignment)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) loadRoleRequests(ctx context.Context, workspaceID, status string, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	predicates := []ormbuilder.Predicate{}
	if strings.TrimSpace(status) != "" {
		predicates = append(predicates, ormbuilder.Equal("status", status))
	}
	if strings.TrimSpace(userID) != "" {
		predicates = append(predicates, ormbuilder.Equal("user_id", userID))
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_role_requests", workspaceID).
		Columns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note").
		OrderBy(ormbuilder.Descending("created_at"), ormbuilder.Ascending("id"))
	if len(predicates) > 0 {
		builder.Where(ormbuilder.And(predicates...))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role request list: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRoleRequest{}
	for rows.Next() {
		var request identitymodel.IdentityRoleRequest
		var provider sql.NullString
		var requestedBy sql.NullString
		var providerSubject sql.NullString
		var roleIDsJSON string
		var reason sql.NullString
		var reviewedBy sql.NullString
		var reviewedAt sql.NullString
		var reviewNote sql.NullString
		if err := rows.Scan(&request.ID, &request.UserID, &requestedBy, &provider, &providerSubject, &roleIDsJSON, &request.Status, &reason, &request.CreatedAt, &request.UpdatedAt, &reviewedBy, &reviewedAt, &reviewNote); err != nil {
			return nil, err
		}
		request.Provider = valueFromNull(provider)
		request.RequestedBy = valueFromNull(requestedBy)
		request.ProviderSubject = valueFromNull(providerSubject)
		_ = json.Unmarshal([]byte(roleIDsJSON), &request.RoleIDs)
		request.Reason = valueFromNull(reason)
		request.ReviewedBy = valueFromNull(reviewedBy)
		request.ReviewedAt = valueFromNull(reviewedAt)
		request.ReviewNote = valueFromNull(reviewNote)
		out = append(out, request)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) memoryRole(ctx context.Context, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	roles, err := s.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	for _, role := range roles {
		if role.ID == roleID {
			return role, true, nil
		}
	}
	return identitymodel.IdentityRole{}, false, nil
}
