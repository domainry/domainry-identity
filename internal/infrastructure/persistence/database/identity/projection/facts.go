package projection

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/domainry/domainry-orm/batch"
	"sort"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
)

const BatchMaxItems = 500

func (s Store) ListUserFacts(ctx context.Context, workspaceID string, userIDs []string) (identitymodel.IdentityUserProjectionFacts, error) {
	facts := identitymodel.IdentityUserProjectionFacts{RoleAssignments: []identitymodel.IdentityUserRoleAssignment{}, ProfileBindings: []identitymodel.IdentityProfileBinding{}}
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return facts, err
	}
	userIDs = uniqueSortedStrings(userIDs)
	if len(userIDs) == 0 {
		return facts, nil
	}
	ranges, err := (batch.Parameters{Max: s.backend.MaxParameters(), Fixed: 1, PerItem: 1, MaxItems: BatchMaxItems}).Ranges(len(userIDs))
	if err != nil {
		return facts, fmt.Errorf("build identity projection query batches: %w", err)
	}
	for _, batch := range ranges {
		batchUserIDs := userIDs[batch.Start:batch.End]
		if err := s.appendIdentityProjectionRoles(ctx, workspaceID, batchUserIDs, &facts); err != nil {
			return facts, err
		}
		if err := s.appendIdentityProjectionBindings(ctx, workspaceID, batchUserIDs, &facts); err != nil {
			return facts, err
		}
	}
	return facts, nil
}

func (s Store) appendIdentityProjectionRoles(ctx context.Context, workspaceID string, userIDs []string, facts *identitymodel.IdentityUserProjectionFacts) error {
	queryValue, args, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).
		Columns("user_id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
		Where(query.In("user_id", stringValues(userIDs)...)).Build()
	if err != nil {
		return err
	}
	rows, err := s.backend.QueryIdentityContext(ctx, queryValue, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var assignment identitymodel.IdentityUserRoleAssignment
		var bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
		if err := rows.Scan(&assignment.UserID, &assignment.RoleID, &bindingKey, &profileID, &assignment.Source, &assignment.Status, &validFrom, &validUntil, &grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &assignment.CreatedAt, &assignment.UpdatedAt); err != nil {
			return err
		}
		assignment.BindingKey, assignment.ProfileID = bindingKey.String, profileID.String
		assignment.ValidFrom, assignment.ValidUntil, assignment.GrantedBy, assignment.GrantReason = validFrom.String, validUntil.String, grantedBy.String, grantReason.String
		assignment.RevokedBy, assignment.RevokedAt, assignment.RevokeReason, assignment.ExpiresAt = revokedBy.String, revokedAt.String, revokeReason.String, pointerFromNull(expiresAt)
		facts.RoleAssignments = append(facts.RoleAssignments, assignment)
	}
	return rows.Err()
}

func (s Store) appendIdentityProjectionBindings(ctx context.Context, workspaceID string, userIDs []string, facts *identitymodel.IdentityUserProjectionFacts) error {
	queryValue, args, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_profile_bindings", workspaceID).
		Columns("workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at").
		Where(query.In("identity_user_id", stringValues(userIDs)...)).Build()
	if err != nil {
		return err
	}
	rows, err := s.backend.QueryIdentityContext(ctx, queryValue, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		binding, err := scanIdentityProfileBinding(rows)
		if err != nil {
			return err
		}
		facts.ProfileBindings = append(facts.ProfileBindings, binding)
	}
	return rows.Err()
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func pointerFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
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
