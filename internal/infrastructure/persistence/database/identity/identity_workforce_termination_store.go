package identity

import (
	"context"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
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
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_workforce_assignments", workspaceID).
		Set("status", "disabled").Set("effective_to", strings.TrimSpace(mutation.EffectiveAt)).
		SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("workforce_profile_id", result.Profile.ID), ormbuilder.Equal("status", "active"))).Build()
	if err != nil {
		return result, err
	}
	assignmentResult, err := tx.ExecContext(ctx, statement, arguments...)
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
	entitlementResult, err := s.revokeWorkforceEntitlements(ctx, tx, workspaceID, result.Profile.ID, actorID, valueOrFallback(strings.TrimSpace(mutation.Reason), "workforce_terminated"), now)
	if err != nil {
		return result, err
	}
	if result.RevokedEntitlementCount, err = entitlementResult.RowsAffected(); err != nil {
		return result, err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_profile_bindings", workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("identity_user_id", result.Profile.IdentityUserID)).Build()
	if err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&result.PreservedProfileBindings); err != nil {
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
