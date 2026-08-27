package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ListIdentityUserDirectoryFacts(ctx context.Context, workspaceID string, userIDs []string) (identitymodel.IdentityUserDirectoryFacts, error) {
	facts := identitymodel.IdentityUserDirectoryFacts{
		RoleAssignments: []identitymodel.IdentityUserRoleAssignment{}, WorkforceProfiles: []identitymodel.IdentityWorkforceProfile{}, ProfileBindings: []identitymodel.IdentityProfileBinding{},
	}
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil || len(userIDs) == 0 {
		return facts, err
	}
	in, args := s.identityUserDirectoryIN(workspaceID, userIDs)
	roleRows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+s.identityColumns("user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at")+
		" FROM "+s.tableIdentifier("identity_user_role_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" IN ("+in+")", args...)
	if err != nil {
		return facts, err
	}
	for roleRows.Next() {
		var assignment identitymodel.IdentityUserRoleAssignment
		var workforceID, bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
		if err := roleRows.Scan(&assignment.UserID, &assignment.RoleID, &workforceID, &bindingKey, &profileID, &assignment.Source, &assignment.Status, &validFrom, &validUntil, &grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &assignment.CreatedAt, &assignment.UpdatedAt); err != nil {
			roleRows.Close()
			return facts, err
		}
		assignment.WorkforceProfileID, assignment.BindingKey, assignment.ProfileID = workforceID.String, bindingKey.String, profileID.String
		assignment.ValidFrom, assignment.ValidUntil, assignment.GrantedBy, assignment.GrantReason = validFrom.String, validUntil.String, grantedBy.String, grantReason.String
		assignment.RevokedBy, assignment.RevokedAt, assignment.RevokeReason, assignment.ExpiresAt = revokedBy.String, revokedAt.String, revokeReason.String, pointerFromNull(expiresAt)
		facts.RoleAssignments = append(facts.RoleAssignments, assignment)
	}
	if err := roleRows.Err(); err != nil {
		_ = roleRows.Close()
		return facts, err
	}
	_ = roleRows.Close()
	profileRows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+s.identityColumns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version")+
		" FROM "+s.tableIdentifier("identity_workforce_profiles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("identity_user_id")+" IN ("+in+")", args...)
	if err != nil {
		return facts, err
	}
	for profileRows.Next() {
		profile, scanErr := scanIdentityWorkforceProfile(profileRows)
		if scanErr != nil {
			profileRows.Close()
			return facts, scanErr
		}
		facts.WorkforceProfiles = append(facts.WorkforceProfiles, profile)
	}
	if err := profileRows.Err(); err != nil {
		_ = profileRows.Close()
		return facts, err
	}
	_ = profileRows.Close()
	bindingRows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+s.identityColumns("workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at")+
		" FROM "+s.tableIdentifier("identity_profile_bindings")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("identity_user_id")+" IN ("+in+")", args...)
	if err != nil {
		return facts, err
	}
	defer bindingRows.Close()
	for bindingRows.Next() {
		binding, scanErr := scanIdentityProfileBinding(bindingRows)
		if scanErr != nil {
			return facts, scanErr
		}
		facts.ProfileBindings = append(facts.ProfileBindings, binding)
	}
	return facts, bindingRows.Err()
}

func (s *SQLIdentityStore) identityUserDirectoryIN(workspaceID string, userIDs []string) (string, []any) {
	args := make([]any, 1, len(userIDs)+1)
	args[0] = workspaceID
	placeholders := make([]string, len(userIDs))
	for index, userID := range userIDs {
		args = append(args, userID)
		placeholders[index] = s.placeholder(index + 2)
	}
	return joinComma(placeholders), args
}

func joinComma(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += ", " + value
	}
	return result
}
