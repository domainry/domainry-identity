package lifecycle

import (
	"context"
	"database/sql"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type UserWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityUser) error
type ProfileWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityWorkforceProfile) error
type AssignmentWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityWorkforceAssignment) error
type RoleAssignmentWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityUserRoleAssignment) error

type Store struct {
	backend             Backend
	now                 func() string
	writeUser           UserWriter
	writeProfile        ProfileWriter
	writeAssignment     AssignmentWriter
	writeRoleAssignment RoleAssignmentWriter
}

func New(backend Backend, now func() string, writeUser UserWriter, writeProfile ProfileWriter, writeAssignment AssignmentWriter, writeRoleAssignment RoleAssignmentWriter) Store {
	return Store{backend: backend, now: now, writeUser: writeUser, writeProfile: writeProfile, writeAssignment: writeAssignment, writeRoleAssignment: writeRoleAssignment}
}

func (s Store) Apply(ctx context.Context, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	result := lifecycleResult(mutation)
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	result, err = s.ApplyTx(ctx, tx, workspaceID, mutation)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s Store) ApplyTx(ctx context.Context, tx *sql.Tx, workspaceID string, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	result := lifecycleResult(mutation)
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return result, err
	}
	now := s.now()
	if mutation.Profile != nil {
		if err := s.writeProfile(ctx, tx, workspaceID, *mutation.Profile); err != nil {
			return result, err
		}
	}
	for _, ending := range mutation.EndAssignments {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "identity_workforce_assignments", workspaceID).
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
		if err := s.writeAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return result, err
		}
	}
	if mutation.RevokeEntitlements {
		actorID := fallback(strings.TrimSpace(mutation.ActorID), "runtime-workforce-lifecycle")
		profileID := ""
		if mutation.Profile != nil {
			profileID = mutation.Profile.ID
		}
		revoked, revokeErr := s.revokeEntitlements(ctx, tx, workspaceID, profileID, actorID, fallback(strings.TrimSpace(mutation.Reason), "workforce_access_revoked"), now)
		if revokeErr != nil {
			return result, revokeErr
		}
		result.RevokedEntitlementCount, err = revoked.RowsAffected()
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s Store) Onboard(ctx context.Context, mutation identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	result := identitymodel.IdentityWorkforceOnboardingResult{User: mutation.User, Profile: mutation.Profile, Assignment: mutation.Assignment, RoleAssignments: append([]identitymodel.IdentityUserRoleAssignment(nil), mutation.RoleAssignments...)}
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err := s.writeUser(ctx, tx, workspaceID, mutation.User); err != nil {
		return result, err
	}
	if err := s.writeProfile(ctx, tx, workspaceID, mutation.Profile); err != nil {
		return result, err
	}
	if err := s.writeAssignment(ctx, tx, workspaceID, mutation.Assignment); err != nil {
		return result, err
	}
	for _, assignment := range mutation.RoleAssignments {
		if err := s.writeRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s Store) Terminate(ctx context.Context, mutation identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error) {
	result := identitymodel.IdentityWorkforceTerminationResult{Profile: mutation.Profile}
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(mutation.Profile.ID) == "" || strings.TrimSpace(mutation.Profile.IdentityUserID) == "" {
		return result, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.workforce_profile_invalid"}
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := s.now()
	if result.Profile.Version > 0 {
		result.Profile.Version++
	}
	if err := s.writeProfile(ctx, tx, workspaceID, result.Profile); err != nil {
		return result, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "identity_workforce_assignments", workspaceID).
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
	entitlementResult, err := s.revokeEntitlements(ctx, tx, workspaceID, result.Profile.ID, fallback(strings.TrimSpace(mutation.ActorID), "runtime-workforce-termination"), fallback(strings.TrimSpace(mutation.Reason), "workforce_terminated"), now)
	if err != nil {
		return result, err
	}
	if result.RevokedEntitlementCount, err = entitlementResult.RowsAffected(); err != nil {
		return result, err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_profile_bindings", workspaceID).
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

func (s Store) revokeEntitlements(ctx context.Context, tx *sql.Tx, workspaceID, profileID, actorID, reason, now string) (sql.Result, error) {
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "identity_user_role_assignments", workspaceID).
		Set("status", "revoked").Set("revoked_by", actorID).Set("revoked_at", now).Set("revoke_reason", reason).Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("workforce_profile_id", profileID), ormbuilder.Equal("status", "active"))).Build()
	if err != nil {
		return nil, err
	}
	return tx.ExecContext(ctx, statement, arguments...)
}

func lifecycleResult(mutation identitymodel.IdentityWorkforceLifecycleMutation) identitymodel.IdentityWorkforceLifecycleResult {
	return identitymodel.IdentityWorkforceLifecycleResult{Profile: mutation.Profile, Assignments: append([]identitymodel.IdentityWorkforceAssignment(nil), mutation.UpsertAssignments...)}
}

func workspaceIdentifier(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}

func fallback(value, defaultValue string) string {
	if value != "" {
		return value
	}
	return defaultValue
}
