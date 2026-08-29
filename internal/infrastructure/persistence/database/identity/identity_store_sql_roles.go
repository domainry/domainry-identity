package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
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
	if _, err := s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_roles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, role.ID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.tableIdentifier("identity_roles") + " (" + s.identityColumns("id", "workspace_id", "role_key", "label", "description", "status", "created_at", "updated_at") + ") VALUES (" + s.placeholders(8) + ")"
	if _, err := s.db.ExecContext(ctx, query, role.ID, workspaceID, role.Key, role.Label, role.Description, string(role.Status), now, now); err != nil {
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
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier(table)+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("role_id")+" = "+s.placeholder(2), workspaceID, roleID); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_roles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, roleID); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) AssignIdentityUserRole(ctx context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.writeIdentityUserRoleAssignment(ctx, s.db, workspaceID, assignment)
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignment(ctx context.Context, execer identityUserExecer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	assignment, err = normalizeIdentityUserRoleAssignment(assignment)
	if err != nil {
		return err
	}
	if _, err := execer.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_user_role_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" = "+s.placeholder(2)+" AND "+s.identifier("role_id")+" = "+s.placeholder(3), workspaceID, assignment.UserID, assignment.RoleID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.tableIdentifier("identity_user_role_assignments") + " (" + s.identityColumns(identityUserRoleAssignmentColumns...) + ") VALUES (" + s.placeholders(len(identityUserRoleAssignmentColumns)) + ")"
	_, err = execer.ExecContext(ctx, query, identityUserRoleAssignmentValues(workspaceID, assignment, nowString())...)
	return err
}

var identityUserRoleAssignmentColumns = []string{"id", "workspace_id", "user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at"}

func normalizeIdentityUserRoleAssignment(assignment identitymodel.IdentityUserRoleAssignment) (identitymodel.IdentityUserRoleAssignment, error) {
	if assignment.UserID == "" || assignment.RoleID == "" {
		return assignment, fmt.Errorf("user id and role id are required")
	}
	assignment.Source = strings.TrimSpace(assignment.Source)
	if assignment.Source == "" {
		assignment.Source = "manual"
	}
	assignment.Status = strings.TrimSpace(assignment.Status)
	if assignment.Status == "" {
		assignment.Status = "active"
	}
	if assignment.ValidUntil == "" && assignment.ExpiresAt != nil {
		assignment.ValidUntil = strings.TrimSpace(*assignment.ExpiresAt)
	}
	return assignment, nil
}

func identityUserRoleAssignmentValues(workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, now string) []any {
	createdAt := strings.TrimSpace(assignment.CreatedAt)
	if createdAt == "" {
		createdAt = now
	}
	return []any{identityID("identity_user_role", workspaceID, assignment.UserID, assignment.RoleID), workspaceID, assignment.UserID, assignment.RoleID,
		nullIfBlank(assignment.WorkforceProfileID), nullIfBlank(assignment.BindingKey), nullIfBlank(assignment.ProfileID), assignment.Source, assignment.Status,
		nullIfBlank(assignment.ValidFrom), nullIfBlank(assignment.ValidUntil), nullIfBlank(assignment.GrantedBy), nullIfBlank(assignment.GrantReason),
		nullIfBlank(assignment.RevokedBy), nullIfBlank(assignment.RevokedAt), nullIfBlank(assignment.RevokeReason), nullableString(assignment.ExpiresAt), createdAt, now}
}

func (s *SQLIdentityStore) RemoveIdentityUserRole(ctx context.Context, workspaceID, userID string, roleID string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_user_role_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" = "+s.placeholder(2)+" AND "+s.identifier("role_id")+" = "+s.placeholder(3), workspaceID, userID, roleID)
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
	if err := s.ensureRoleRequestsTable(ctx); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
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
	query := "INSERT INTO " + s.tableIdentifier("identity_role_requests") + " (" + s.identityColumns("id", "workspace_id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note") + ") VALUES (" + s.placeholders(14) + ")"
	if _, err := s.db.ExecContext(ctx, query, request.ID, workspaceID, request.UserID, nullableText(request.RequestedBy), nullableText(request.Provider), nullableText(request.ProviderSubject), string(roleIDsJSON), request.Status, nullableText(request.Reason), request.CreatedAt, request.UpdatedAt, nullableText(request.ReviewedBy), nullableText(request.ReviewedAt), nullableText(request.ReviewNote)); err != nil {
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
	query := "UPDATE " + s.tableIdentifier("identity_role_requests") + " SET " + s.identifier("role_ids_json") + " = " + s.placeholder(1) + ", " + s.identifier("status") + " = " + s.placeholder(2) + ", " + s.identifier("reason") + " = " + s.placeholder(3) + ", " + s.identifier("updated_at") + " = " + s.placeholder(4) + ", " + s.identifier("reviewed_by") + " = " + s.placeholder(5) + ", " + s.identifier("reviewed_at") + " = " + s.placeholder(6) + ", " + s.identifier("review_note") + " = " + s.placeholder(7) + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(8) + " AND " + s.identifier("id") + " = " + s.placeholder(9)
	if _, err := s.db.ExecContext(ctx, query, string(roleIDsJSON), request.Status, nullableText(request.Reason), request.UpdatedAt, nullableText(request.ReviewedBy), nullableText(request.ReviewedAt), nullableText(request.ReviewNote), workspaceID, request.ID); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) ApplyIdentityRoleRequestDecision(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.ensureRoleRequestsTable(ctx); err != nil {
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
	query := "UPDATE " + s.tableIdentifier("identity_role_requests") + " SET " +
		s.identifier("role_ids_json") + " = " + s.placeholder(1) + ", " + s.identifier("status") + " = " + s.placeholder(2) + ", " +
		s.identifier("reason") + " = " + s.placeholder(3) + ", " + s.identifier("updated_at") + " = " + s.placeholder(4) + ", " +
		s.identifier("reviewed_by") + " = " + s.placeholder(5) + ", " + s.identifier("reviewed_at") + " = " + s.placeholder(6) + ", " +
		s.identifier("review_note") + " = " + s.placeholder(7) + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(8) +
		" AND " + s.identifier("id") + " = " + s.placeholder(9) + " AND " + s.identifier("status") + " = " + s.placeholder(10)
	result, err := tx.ExecContext(ctx, query, string(roleIDsJSON), request.Status, nullableText(request.Reason), request.UpdatedAt, nullableText(request.ReviewedBy), nullableText(request.ReviewedAt), nullableText(request.ReviewNote), workspaceID, request.ID, expectedStatus)
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

func (s *SQLIdentityStore) loadRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+s.identityColumns("id", "role_key", "label", "description", "status")+" FROM "+s.tableIdentifier("identity_roles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" ORDER BY "+s.identifier("id"), workspaceID)
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
	query := "SELECT " + s.identityColumns("user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at") + " FROM " + s.tableIdentifier("identity_user_role_assignments")
	args := []any{workspaceID}
	query += " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1)
	if strings.TrimSpace(userID) != "" {
		args = append(args, userID)
		query += " AND " + s.identifier("user_id") + " = " + s.placeholder(2)
	}
	query += " ORDER BY " + s.identifier("user_id") + ", " + s.identifier("role_id")
	rows, err := s.reader(ctx).QueryContext(ctx, query, args...)
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
	if err := s.ensureRoleRequestsTable(ctx); err != nil {
		return nil, err
	}
	query := "SELECT " + s.identityColumns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note") + " FROM " + s.tableIdentifier("identity_role_requests")
	args := []any{workspaceID}
	where := []string{s.identifier("workspace_id") + " = " + s.placeholder(1)}
	if strings.TrimSpace(status) != "" {
		args = append(args, status)
		where = append(where, s.identifier("status")+" = "+s.placeholder(len(args)))
	}
	if strings.TrimSpace(userID) != "" {
		args = append(args, userID)
		where = append(where, s.identifier("user_id")+" = "+s.placeholder(len(args)))
	}
	query += " WHERE " + strings.Join(where, " AND ")
	query += " ORDER BY " + s.identifier("created_at") + " DESC, " + s.identifier("id")
	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *SQLIdentityStore) ensureRoleRequestsTable(ctx context.Context) error {
	if s.roleRequestsReady.Load() {
		return nil
	}
	schemaDB := s.schemaDB
	if schemaDB == nil {
		schemaDB = s.db
	}
	if schemaDB == nil {
		return fmt.Errorf("identity role request schema database unavailable")
	}
	key := func(name string) ormbuilder.SchemaColumn {
		return ormbuilder.DefineColumn(name, ormbuilder.TextKeyType(255))
	}
	text := func(name string) ormbuilder.SchemaColumn { return ormbuilder.DefineColumn(name, ormbuilder.TextType()) }
	create, _, err := ormbuilder.NewCreateTableBuilder(s.sqlRenderer(), "identity_role_requests").IfNotExists().WithoutSystemColumns().Columns(
		key("id").NotNull(), key("workspace_id").NotNull(), key("user_id").NotNull(), key("requested_by"),
		key("provider"), key("provider_subject"), text("role_ids_json").NotNull(), key("status").NotNull(),
		text("reason"), key("created_at").NotNull(), key("updated_at").NotNull(), key("reviewed_by"),
		key("reviewed_at"), text("review_note"),
	).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return fmt.Errorf("build identity role-request schema: %w", err)
	}
	if _, err := schemaDB.ExecContext(ctx, create); err != nil {
		return err
	}
	addRequestedBy, _, err := ormbuilder.NewAddColumnBuilder(s.sqlRenderer(), "identity_role_requests", key("requested_by")).Build()
	if err != nil {
		return fmt.Errorf("build identity role-request requested-by migration: %w", err)
	}
	if _, err := schemaDB.ExecContext(ctx, addRequestedBy); err != nil {
		message := strings.ToLower(err.Error())
		if !strings.Contains(message, "duplicate") && !strings.Contains(message, "already exists") {
			return err
		}
	}
	s.roleRequestsReady.Store(true)
	return nil
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
