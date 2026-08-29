package identity

import (
	"context"
	"database/sql"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
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
		statement, arguments, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_workforce_assignments", workspaceID).
			Set("status", "disabled").Set("effective_to", strings.TrimSpace(ending.EffectiveTo)).
			SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).Set("updated_at", now).
			Where(ormbuilder.And(ormbuilder.Equal("id", strings.TrimSpace(ending.AssignmentID)), ormbuilder.Equal("status", "active"))).Build()
		if buildErr != nil {
			return result, buildErr
		}
		ended, updateErr := tx.ExecContext(ctx, statement, arguments...)
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
		revoked, revokeErr := s.revokeWorkforceEntitlements(ctx, tx, workspaceID, profileID, actorID, valueOrFallback(strings.TrimSpace(mutation.Reason), "workforce_access_revoked"), now)
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

func (s *SQLIdentityStore) revokeWorkforceEntitlements(ctx context.Context, tx *sql.Tx, workspaceID, profileID, actorID, reason, now string) (sql.Result, error) {
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_user_role_assignments", workspaceID).
		Set("status", "revoked").Set("revoked_by", actorID).Set("revoked_at", now).Set("revoke_reason", reason).Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("workforce_profile_id", profileID), ormbuilder.Equal("status", "active"))).Build()
	if err != nil {
		return nil, err
	}
	return tx.ExecContext(ctx, statement, arguments...)
}
