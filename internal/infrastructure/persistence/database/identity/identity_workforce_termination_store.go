package identity

import (
	"context"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) TerminateIdentityWorkforce(ctx context.Context, mutation identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error) {
	result := identitymodel.IdentityWorkforceTerminationResult{Profile: mutation.Profile}
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(mutation.Profile.ID) == "" || strings.TrimSpace(mutation.Profile.IdentityUserID) == "" {
		return result, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.workforce_profile_invalid"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if result.Profile.Version > 0 {
		result.Profile.Version++
	}
	if err := s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, result.Profile); err != nil {
		return result, err
	}
	assignmentResult, err := tx.ExecContext(ctx,
		"UPDATE "+s.tableIdentifier("identity_workforce_assignments")+
			" SET "+s.identifier("status")+" = 'disabled', "+s.identifier("effective_to")+" = "+s.placeholder(1)+
			", "+s.identifier("version")+" = "+s.identifier("version")+" + 1, "+s.identifier("updated_at")+" = "+s.placeholder(2)+
			" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("workforce_profile_id")+" = "+s.placeholder(4)+
			" AND "+s.identifier("status")+" = 'active'",
		strings.TrimSpace(mutation.EffectiveAt), now, workspaceID, result.Profile.ID,
	)
	if err != nil {
		return result, err
	}
	if result.EndedAssignmentCount, err = assignmentResult.RowsAffected(); err != nil {
		return result, err
	}
	actorID := strings.TrimSpace(mutation.ActorID)
	if actorID == "" {
		actorID = "runtime-workforce-termination"
	}
	entitlementResult, err := tx.ExecContext(ctx,
		"UPDATE "+s.tableIdentifier("identity_user_role_assignments")+
			" SET "+s.identifier("status")+" = 'revoked', "+s.identifier("revoked_by")+" = "+s.placeholder(1)+
			", "+s.identifier("revoked_at")+" = "+s.placeholder(2)+", "+s.identifier("revoke_reason")+" = "+s.placeholder(3)+
			", "+s.identifier("updated_at")+" = "+s.placeholder(4)+
			" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(5)+" AND "+s.identifier("workforce_profile_id")+" = "+s.placeholder(6)+
			" AND "+s.identifier("status")+" = 'active'",
		actorID, now, valueOrFallback(strings.TrimSpace(mutation.Reason), "workforce_terminated"), now, workspaceID, result.Profile.ID,
	)
	if err != nil {
		return result, err
	}
	if result.RevokedEntitlementCount, err = entitlementResult.RowsAffected(); err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM "+s.tableIdentifier("identity_profile_bindings")+
			" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("identity_user_id")+" = "+s.placeholder(2),
		workspaceID, result.Profile.IdentityUserID,
	).Scan(&result.PreservedProfileBindings); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
