package identity

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

// IdentitySessionRevoker is the account-security boundary required by the
// account-disable use case. Business identities are deliberately outside this
// contract: disabling sign-in must not mutate profile state.
type IdentitySessionRevoker interface {
	ForceLogoutUser(context.Context, string, string) (int, error)
}

type IdentityUserDeletionInspection struct {
	BusinessProfileReferences []identitymodel.IdentityUserRecordReference
	OwnedRecordReferences     []identitymodel.IdentityUserRecordReference
	PendingApprovalTaskIDs    []string
	RetainedAuditEventIDs     []string
	ActiveLegalHoldIDs        []string
}

type IdentityUserDeletionInspector interface {
	InspectIdentityUserDeletion(context.Context, string, string) (IdentityUserDeletionInspection, error)
}

func (s *IdentityApplicationService) domainForContext(ctx context.Context) (*identitydomain.IdentityDomainService, error) {
	workspaceID := requestcontext.WorkspaceID(ctx)
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return nil, apperror.New(apperror.KindForbidden, "backend.workspace_scope_required", err, nil)
	}
	return s.IdentityDomainService.ForWorkspace(workspaceID)
}

func (s *IdentityApplicationService) ListMenus(ctx context.Context) ([]identitymodel.IdentityMenu, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListMenus(ctx)
}

func (s *IdentityApplicationService) EffectiveMenus(ctx context.Context, userID string) ([]identitymodel.IdentityMenu, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.EffectiveMenus(ctx, userID)
}

func (s *IdentityApplicationService) ResolvePrincipal(ctx context.Context, userID string) (identitymodel.Principal, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	return scoped.ResolvePrincipal(ctx, userID)
}

func (s *IdentityApplicationService) ResolvePrincipalForRole(ctx context.Context, userID, roleKey string) (identitymodel.Principal, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	return scoped.ResolvePrincipalForRole(ctx, userID, roleKey)
}

func (s *IdentityApplicationService) ResolveEffectivePermissions(ctx context.Context, userID string) ([]string, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ResolveEffectivePermissions(ctx, userID)
}

func (s *IdentityApplicationService) ResolveEffectiveMenus(ctx context.Context, userID string) ([]identitymodel.IdentityMenu, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ResolveEffectiveMenus(ctx, userID)
}

func (s *IdentityApplicationService) FindUser(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	return scoped.FindUser(ctx, userID)
}

func (s *IdentityApplicationService) FindOrganizationUnit(ctx context.Context, organizationUnitID string) (identitymodel.IdentityOrganizationUnit, bool, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, err
	}
	return scoped.FindOrganizationUnit(ctx, organizationUnitID)
}

func (s *IdentityApplicationService) ListDirectoryUsers(ctx context.Context) ([]identitymodel.IdentityUser, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListDirectoryUsers(ctx)
}

func (s *IdentityApplicationService) ListDirectoryRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListDirectoryRoles(ctx)
}

func (s *IdentityApplicationService) ListDirectoryUserRoleAssignments(ctx context.Context, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListDirectoryUserRoleAssignments(ctx, userID)
}

func (s *IdentityApplicationService) ListOrganizationUnits(ctx context.Context) ([]identitymodel.IdentityOrganizationUnit, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListOrganizationUnits(ctx)
}

func (s *IdentityApplicationService) UpsertOrganizationUnit(ctx context.Context, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.UpsertOrganizationUnit(ctx, organizationUnit)
}

func (s *IdentityApplicationService) ListUsers(ctx context.Context) ([]identitymodel.IdentityUser, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListUsers(ctx)
}

func (s *IdentityApplicationService) SearchUsers(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	return scoped.SearchUsers(ctx, query)
}

func (s *IdentityApplicationService) UserByID(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	return scoped.UserByID(ctx, userID)
}

func (s *IdentityApplicationService) UserByLogin(ctx context.Context, login string) (identitymodel.IdentityUser, bool, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	return scoped.UserByLogin(ctx, login)
}

func (s *IdentityApplicationService) UpsertUser(ctx context.Context, user identitymodel.IdentityUser) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.UpsertUser(ctx, user)
}

func (s *IdentityApplicationService) RemoveUser(ctx context.Context, userID string) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	impact, err := s.UserDeletionImpact(ctx, userID)
	if err != nil {
		return err
	}
	if !impact.CanDelete {
		return apperror.New(apperror.KindConflict, "backend.identity.user_deletion_blocked", nil, map[string]string{
			"user": strings.TrimSpace(userID), "blockers": strings.Join(impact.Blockers, ","),
		})
	}
	return scoped.RemoveUser(ctx, userID)
}

func (s *IdentityApplicationService) UserDeletionImpact(ctx context.Context, userID string) (identitymodel.IdentityUserDeletionImpact, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	}
	impact, err := scoped.UserDeletionImpact(ctx, userID)
	if err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	}
	if s.userDeletionInspector == nil {
		return identitymodel.IdentityUserDeletionImpact{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_deletion_inspector_unavailable", nil, nil)
	}
	inspection, err := s.userDeletionInspector.InspectIdentityUserDeletion(ctx, scoped.WorkspaceID(), strings.TrimSpace(userID))
	if err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	}
	impact.BusinessProfileReferences = append([]identitymodel.IdentityUserRecordReference{}, inspection.BusinessProfileReferences...)
	impact.OwnedRecordReferences = append([]identitymodel.IdentityUserRecordReference{}, inspection.OwnedRecordReferences...)
	impact.PendingApprovalTaskIDs = append([]string{}, inspection.PendingApprovalTaskIDs...)
	impact.RetainedAuditEventIDs = append([]string{}, inspection.RetainedAuditEventIDs...)
	impact.ActiveLegalHoldIDs = append([]string{}, inspection.ActiveLegalHoldIDs...)
	impact.Blockers = identityUserDeletionBlockers(impact)
	impact.CanDelete = len(impact.Blockers) == 0
	return impact, nil
}

func (s *IdentityApplicationService) UserDisableImpact(ctx context.Context, userID string) (identitymodel.IdentityUserDisableImpact, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUserDisableImpact{}, err
	}
	impact, err := scoped.UserDeletionImpact(ctx, userID)
	if err != nil {
		return identitymodel.IdentityUserDisableImpact{}, err
	}
	return identitymodel.IdentityUserDisableImpact{
		UserID: impact.UserID, ProfileBindings: append([]identitymodel.IdentityProfileBinding{}, impact.ProfileBindings...),
		ActiveEntitlementRoleIDs: append([]string{}, impact.ActiveRoleIDs...),
		SessionsWillBeRevoked:    true, BusinessFactsPreserved: true,
	}, nil
}

func identityUserDeletionBlockers(impact identitymodel.IdentityUserDeletionImpact) []string {
	blockers := []string{}
	for code, blocked := range map[string]bool{
		"business_profile": len(impact.ProfileBindings) > 0 || len(impact.BusinessProfileReferences) > 0,
		"record_ownership": len(impact.OwnedRecordReferences) > 0,
		"approval_task":    len(impact.PendingApprovalTaskIDs) > 0,
		"audit_retention":  len(impact.RetainedAuditEventIDs) > 0,
		"legal_hold":       len(impact.ActiveLegalHoldIDs) > 0,
	} {
		if blocked {
			blockers = append(blockers, code)
		}
	}
	sort.Strings(blockers)
	return blockers
}

func (s *IdentityApplicationService) SetUserStatus(ctx context.Context, userID string, status identitymodel.IdentityStatus) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.SetUserStatus(ctx, userID, status)
}

func (s *IdentityApplicationService) EnableUser(ctx context.Context, userID string) error {
	return s.SetUserStatus(ctx, strings.TrimSpace(userID), identitymodel.IdentityStatusActive)
}

func (s *IdentityApplicationService) DisableUser(ctx context.Context, userID string, sessions IdentitySessionRevoker) (int, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return 0, err
	}
	userID = strings.TrimSpace(userID)
	if repository, ok := scoped.Repository().(identityrepository.IdentityAccountDisableRepository); ok {
		return repository.DisableIdentityAccount(ctx, scoped.WorkspaceID(), userID)
	}
	if sessions == nil {
		return 0, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.user_security_unavailable"}
	}
	if err := scoped.SetUserStatus(ctx, userID, identitymodel.IdentityStatusDisabled); err != nil {
		return 0, err
	}
	return sessions.ForceLogoutUser(ctx, scoped.WorkspaceID(), userID)
}
