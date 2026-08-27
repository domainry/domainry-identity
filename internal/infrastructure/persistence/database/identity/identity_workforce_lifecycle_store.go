package identity

import (
	"context"
	"database/sql"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ApplyIdentityWorkforceLifecycle(ctx context.Context, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	result := identitymodel.IdentityWorkforceLifecycleResult{
		Profile: mutation.Profile, Assignments: append([]identitymodel.IdentityWorkforceAssignment(nil), mutation.UpsertAssignments...),
	}
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	result, err = s.applyIdentityWorkforceLifecycleTx(ctx, tx, workspaceID, mutation)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *SQLIdentityStore) applyIdentityWorkforceLifecycleTx(ctx context.Context, tx *sql.Tx, workspaceID string, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	result := identitymodel.IdentityWorkforceLifecycleResult{
		Profile: mutation.Profile, Assignments: append([]identitymodel.IdentityWorkforceAssignment(nil), mutation.UpsertAssignments...),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if mutation.Profile != nil {
		if err := s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, *mutation.Profile); err != nil {
			return result, err
		}
	}
	for _, ending := range mutation.EndAssignments {
		ended, updateErr := tx.ExecContext(ctx,
			"UPDATE "+s.tableIdentifier("identity_workforce_assignments")+
				" SET "+s.identifier("status")+" = 'disabled', "+s.identifier("effective_to")+" = "+s.placeholder(1)+
				", "+s.identifier("version")+" = "+s.identifier("version")+" + 1, "+s.identifier("updated_at")+" = "+s.placeholder(2)+
				" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("id")+" = "+s.placeholder(4)+
				" AND "+s.identifier("status")+" = 'active'",
			strings.TrimSpace(ending.EffectiveTo), now, workspaceID, strings.TrimSpace(ending.AssignmentID),
		)
		if updateErr != nil {
			return result, updateErr
		}
		count, countErr := ended.RowsAffected()
		if countErr != nil {
			return result, countErr
		}
		result.EndedAssignmentCount += count
	}
	for _, assignment := range mutation.UpsertAssignments {
		if err := s.writeIdentityWorkforceAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return result, err
		}
	}
	if mutation.RevokeEntitlements {
		actorID := strings.TrimSpace(mutation.ActorID)
		if actorID == "" {
			actorID = "runtime-workforce-lifecycle"
		}
		profileID := ""
		if mutation.Profile != nil {
			profileID = mutation.Profile.ID
		}
		revoked, revokeErr := tx.ExecContext(ctx,
			"UPDATE "+s.tableIdentifier("identity_user_role_assignments")+
				" SET "+s.identifier("status")+" = 'revoked', "+s.identifier("revoked_by")+" = "+s.placeholder(1)+
				", "+s.identifier("revoked_at")+" = "+s.placeholder(2)+", "+s.identifier("revoke_reason")+" = "+s.placeholder(3)+
				", "+s.identifier("updated_at")+" = "+s.placeholder(4)+
				" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(5)+" AND "+s.identifier("workforce_profile_id")+" = "+s.placeholder(6)+
				" AND "+s.identifier("status")+" = 'active'",
			actorID, now, valueOrFallback(strings.TrimSpace(mutation.Reason), "workforce_access_revoked"), now, workspaceID, profileID,
		)
		if revokeErr != nil {
			return result, revokeErr
		}
		revokedCount, countErr := revoked.RowsAffected()
		if countErr != nil {
			return result, countErr
		}
		result.RevokedEntitlementCount = revokedCount
	}
	return result, nil
}
