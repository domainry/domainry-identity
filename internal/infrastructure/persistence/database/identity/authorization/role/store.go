package role

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store { return &Store{backend: backend, now: now} }

func (s *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_roles", workspaceID).Columns("id", "role_key", "label", "description", "status").OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRole{}
	for rows.Next() {
		var item identitymodel.IdentityRole
		var status string
		if err := rows.Scan(&item.ID, &item.Key, &item.Label, &item.Description, &status); err != nil {
			return nil, err
		}
		item.Status = identitymodel.IdentityStatus(status)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Upsert(ctx context.Context, workspaceID string, item identitymodel.IdentityRole) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("role id is required")
	}
	if item.Key == "" {
		item.Key = item.ID
	}
	if item.Status == "" {
		item.Status = identitymodel.IdentityStatusActive
	}
	now := s.now()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_roles", workspaceID).Columns("id", "role_key", "label", "description", "status", "created_at", "updated_at").Values(item.ID, item.Key, item.Label, item.Description, string(item.Status), now, now)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "role_key", "label", "description", "status", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity role upsert: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) Remove(ctx context.Context, workspaceID, roleID string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	for _, table := range []string{"_identity_user_role_assignments", "_identity_role_menu_assignments"} {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), table, workspaceID).Where(ormbuilder.Equal("role_id", roleID)).Build()
		if buildErr != nil {
			return fmt.Errorf("build identity role relation delete: %w", buildErr)
		}
		if _, err := s.backend.DB().ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_roles", workspaceID).Where(ormbuilder.Equal("id", roleID)).Build()
	if err != nil {
		return fmt.Errorf("build identity role delete: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) RemoveUserAssignment(ctx context.Context, workspaceID, userID, roleID string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("role_id", roleID))).Build()
	if err != nil {
		return fmt.Errorf("build identity user-role assignment delete: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) ListUserAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Columns("user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").OrderBy(ormbuilder.Ascending("user_id"), ormbuilder.Ascending("role_id"))
	if strings.TrimSpace(userID) != "" {
		builder.Where(ormbuilder.Equal("user_id", userID))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity user-role assignment list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityUserRoleAssignment{}
	for rows.Next() {
		var item identitymodel.IdentityUserRoleAssignment
		var workforceProfileID, bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
		if err := rows.Scan(&item.UserID, &item.RoleID, &workforceProfileID, &bindingKey, &profileID, &item.Source, &item.Status, &validFrom, &validUntil, &grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.WorkforceProfileID, item.BindingKey, item.ProfileID = workforceProfileID.String, bindingKey.String, profileID.String
		item.ValidFrom, item.ValidUntil, item.GrantedBy, item.GrantReason = validFrom.String, validUntil.String, grantedBy.String, grantReason.String
		item.RevokedBy, item.RevokedAt, item.RevokeReason = revokedBy.String, revokedAt.String, revokeReason.String
		if expiresAt.Valid {
			value := expiresAt.String
			item.ExpiresAt = &value
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
