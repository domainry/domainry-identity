package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

// IdentityApplicationService owns Identity governance and reference-projection
// use cases. Bootstrap supplies the repository during construction.
type IdentityApplicationService struct {
	*identitydomain.IdentityDomainService
	WorkforceDomainService *identitydomain.IdentityWorkforceDomainService
	workforceRepository    identityrepository.IdentityWorkforceRepository
	workforceTermination   identityrepository.IdentityWorkforceTerminationRepository
	workforceLifecycle     identityrepository.IdentityWorkforceLifecycleRepository
	workforceOnboarding    identityrepository.IdentityWorkforceOnboardingRepository
	userDeletionInspector  IdentityUserDeletionInspector
	positionResolver       IdentityWorkforcePositionResolver
	pagePermissions        identityAdminPagePermissionSource
}

type identityAdminPagePermissionSource interface {
	RequiredPermissionsForPage(string) ([]string, bool)
}

func NewIdentityApplicationService(repository identityrepository.IdentityRepository, permissions []identitymodel.IdentityPermissionDefinition) *IdentityApplicationService {
	return NewIdentityApplicationServiceWithDependencies(repository, permissions, IdentityApplicationServiceDependencies{})
}

func NewIdentityApplicationServiceWithPermissionSource(repository identityrepository.IdentityRepository, source identitydomain.IdentityPermissionDefinitionSource, actions *IdentityActionRegistry) *IdentityApplicationService {
	service := NewIdentityApplicationServiceWithDependencies(repository, nil, IdentityApplicationServiceDependencies{Actions: actions})
	service.IdentityDomainService = identitydomain.NewIdentityDomainServiceWithPermissionSource(repository, source)
	return service
}

type IdentityApplicationServiceDependencies struct {
	UserDeletionInspector IdentityUserDeletionInspector
	PositionResolver      IdentityWorkforcePositionResolver
	Actions               *IdentityActionRegistry
}

type IdentityWorkforcePositionResolver interface {
	ListWorkforcePositions(context.Context, string) ([]identitymodel.IdentityWorkforcePosition, error)
}

func NewIdentityApplicationServiceWithDependencies(repository identityrepository.IdentityRepository, permissions []identitymodel.IdentityPermissionDefinition, dependencies IdentityApplicationServiceDependencies) *IdentityApplicationService {
	deletionInspector := dependencies.UserDeletionInspector
	if deletionInspector == nil {
		deletionInspector = identityLocalDeletionInspector{}
	}
	service := &IdentityApplicationService{
		IdentityDomainService: identitydomain.NewIdentityDomainService(repository, permissions),
		userDeletionInspector: deletionInspector,
		positionResolver:      dependencies.PositionResolver,
		pagePermissions:       identityBuiltinPagePermissions{},
	}
	if dependencies.Actions != nil {
		service.pagePermissions = dependencies.Actions
	}
	if workforce, ok := repository.(identityrepository.IdentityWorkforceRepository); ok {
		service.workforceRepository = workforce
		service.WorkforceDomainService = identitydomain.NewIdentityWorkforceDomainService(repository, workforce)
	}
	if termination, ok := repository.(identityrepository.IdentityWorkforceTerminationRepository); ok {
		service.workforceTermination = termination
	}
	if lifecycle, ok := repository.(identityrepository.IdentityWorkforceLifecycleRepository); ok {
		service.workforceLifecycle = lifecycle
	}
	if onboarding, ok := repository.(identityrepository.IdentityWorkforceOnboardingRepository); ok {
		service.workforceOnboarding = onboarding
	}
	return service
}

// identityLocalDeletionInspector intentionally reports no dependencies outside
// Identity. The domain service still blocks deletion for Identity-owned role,
// workforce, and profile bindings; host-module business records are not part of
// this standalone service.
type identityLocalDeletionInspector struct{}

func (identityLocalDeletionInspector) InspectIdentityUserDeletion(context.Context, string, string) (IdentityUserDeletionInspection, error) {
	return IdentityUserDeletionInspection{}, nil
}

func (s *IdentityApplicationService) ForWorkspace(workspaceID string) (*IdentityApplicationService, error) {
	scoped, err := s.IdentityDomainService.ForWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	clone := &IdentityApplicationService{IdentityDomainService: scoped, workforceRepository: s.workforceRepository, workforceTermination: s.workforceTermination, workforceLifecycle: s.workforceLifecycle, workforceOnboarding: s.workforceOnboarding, userDeletionInspector: s.userDeletionInspector, positionResolver: s.positionResolver, pagePermissions: s.pagePermissions}
	if s.WorkforceDomainService != nil {
		// IdentityDomainService accepted the same workspace identifier above, so
		// the workforce view cannot independently reject it.
		clone.WorkforceDomainService, _ = s.WorkforceDomainService.ForWorkspace(workspaceID)
	}
	return clone, nil
}

func (s *IdentityApplicationService) ListWorkforceProfiles(ctx context.Context) ([]identitymodel.IdentityWorkforceProfile, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return nil, err
	}
	if scoped.workforceRepository == nil {
		return nil, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.workforceRepository.ListIdentityWorkforceProfiles(ctx, scoped.IdentityDomainService.WorkspaceID())
}

func identityWorkforceReadScopeAllows(principal identitymodel.Principal, profile identitymodel.IdentityWorkforceProfile, assignments []identitymodel.IdentityWorkforceAssignment, departments map[string]identitymodel.IdentityDepartment) bool {
	scope := strings.TrimSpace(identitycontract.IdentityDataScope(principal.Role, "identity_workforce_profile", false))
	if scope == "none" {
		scope = strings.TrimSpace(principal.Role.RecordScope)
	}
	if scope == "all_records" {
		return true
	}
	if profile.IdentityUserID == principal.UserID {
		return scope == "owned_records" || scope == "subordinates" || scope == "team" || scope == "department" || scope == "department_and_children"
	}
	switch scope {
	case "subordinates", "team":
		for _, userID := range principal.ReportingUserIDs {
			if strings.TrimSpace(userID) == profile.IdentityUserID {
				return true
			}
		}
	case "department", "department_and_children":
		assignment, ok := workforcePrimaryAssignment(profile, assignments)
		if !ok {
			return false
		}
		if principal.DepartmentID != "" && assignment.OrganizationUnitID == principal.DepartmentID {
			return true
		}
		department, ok := departments[assignment.OrganizationUnitID]
		principalPath := strings.TrimRight(strings.TrimSpace(principal.DepartmentPath), "/")
		targetPath := strings.TrimRight(strings.TrimSpace(department.Path), "/")
		if !ok || principalPath == "" {
			return false
		}
		return targetPath == principalPath || scope == "department_and_children" && strings.HasPrefix(targetPath, principalPath+"/")
	}
	return false
}

func workforcePrimaryAssignment(profile identitymodel.IdentityWorkforceProfile, assignments []identitymodel.IdentityWorkforceAssignment) (identitymodel.IdentityWorkforceAssignment, bool) {
	for _, assignment := range assignments {
		if profile.PrimaryAssignmentID != "" && assignment.ID == profile.PrimaryAssignmentID {
			return assignment, true
		}
	}
	for _, assignment := range assignments {
		if assignment.AssignmentType == identitymodel.IdentityWorkforceAssignmentPrimary && assignment.Status == identitymodel.IdentityStatusActive {
			return assignment, true
		}
	}
	return identitymodel.IdentityWorkforceAssignment{}, false
}

func (s *IdentityApplicationService) SearchWorkforceProfiles(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	return scoped.SearchWorkforceProfiles(ctx, query)
}

func (s *IdentityApplicationService) SearchWorkforceProfilesForPrincipal(ctx context.Context, query identitymodel.IdentityListQuery, principal identitymodel.Principal) (identitymodel.IdentityWorkforceProfilePage, error) {
	if err := identityAuthorizeQuery(principal); err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	query.Scope = identityWorkforceReadScope(principal)
	query.PrincipalUserID = principal.UserID
	query.PrincipalDepartmentPath = principal.DepartmentPath
	query.PrincipalReportingUserIDs = append([]string(nil), principal.ReportingUserIDs...)
	return scoped.SearchWorkforceProfiles(ctx, query)
}

func (s *IdentityApplicationService) GetWorkforceProfile(ctx context.Context, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	if scoped.workforceRepository == nil {
		return identitymodel.IdentityWorkforceProfile{}, false, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.IdentityDomainService.WorkspaceID(), profileID)
}

func (s *IdentityApplicationService) GetWorkforceProfileForPrincipal(ctx context.Context, profileID string, principal identitymodel.Principal) (identitymodel.IdentityWorkforceProfile, bool, error) {
	if err := identityAuthorizeQuery(principal); err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	profile, found, err := s.GetWorkforceProfile(ctx, profileID)
	if err != nil || !found {
		return identitymodel.IdentityWorkforceProfile{}, found, err
	}
	allowed, err := s.canReadWorkforceProfile(ctx, profile, principal)
	if err != nil || !allowed {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	return profile, true, nil
}

func (s *IdentityApplicationService) GetWorkforceDetail(ctx context.Context, profileID string) (identitymodel.IdentityWorkforceDetail, bool, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceDetail{}, false, err
	}
	profile, found, err := scoped.GetWorkforceProfile(ctx, profileID)
	if err != nil || !found {
		return identitymodel.IdentityWorkforceDetail{}, found, err
	}
	account, accountFound, err := scoped.Repository().GetIdentityUser(ctx, scoped.WorkspaceID(), profile.IdentityUserID)
	if err != nil {
		return identitymodel.IdentityWorkforceDetail{}, false, err
	}
	if !accountFound {
		return identitymodel.IdentityWorkforceDetail{}, false, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_user_not_found"}
	}
	assignments, err := scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.WorkspaceID(), profile.ID)
	if err != nil {
		return identitymodel.IdentityWorkforceDetail{}, false, err
	}
	bindings, err := scoped.Repository().ListIdentityProfileBindingsByUser(ctx, scoped.WorkspaceID(), profile.IdentityUserID)
	if err != nil {
		return identitymodel.IdentityWorkforceDetail{}, false, err
	}
	activeBindings := make([]identitymodel.IdentityProfileBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Status != identitymodel.IdentityProfileBindingUnlinked {
			activeBindings = append(activeBindings, binding)
		}
	}
	return identitymodel.IdentityWorkforceDetail{
		Profile: profile, Assignments: assignments, Account: account, BusinessProfiles: activeBindings,
	}, true, nil
}

func (s *IdentityApplicationService) GetWorkforceDetailForPrincipal(ctx context.Context, profileID string, principal identitymodel.Principal) (identitymodel.IdentityWorkforceDetail, bool, error) {
	profile, found, err := s.GetWorkforceProfileForPrincipal(ctx, profileID, principal)
	if err != nil || !found {
		return identitymodel.IdentityWorkforceDetail{}, found, err
	}
	return s.GetWorkforceDetail(ctx, profile.ID)
}

func (s *IdentityApplicationService) UpsertWorkforceProfile(ctx context.Context, profile identitymodel.IdentityWorkforceProfile) error {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return err
	}
	if scoped.WorkforceDomainService == nil {
		return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.WorkforceDomainService.UpsertProfile(ctx, profile)
}

func (s *IdentityApplicationService) ValidateWorkforceProfile(ctx context.Context, profile identitymodel.IdentityWorkforceProfile) error {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return err
	}
	if scoped.WorkforceDomainService == nil {
		return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.WorkforceDomainService.ValidateProfile(ctx, profile)
}

func (s *IdentityApplicationService) TerminateWorkforceProfile(ctx context.Context, profileID, effectiveAt string, requests ...identitymodel.IdentityWorkforceTerminationOptions) (identitymodel.IdentityWorkforceProfile, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, err
	}
	if scoped.WorkforceDomainService == nil {
		return identitymodel.IdentityWorkforceProfile{}, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	if scoped.workforceTermination == nil {
		return identitymodel.IdentityWorkforceProfile{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.workforce_termination_unavailable"}
	}
	profile, err := scoped.WorkforceDomainService.PrepareProfileTermination(ctx, profileID, effectiveAt)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, err
	}
	options := identitymodel.IdentityWorkforceTerminationOptions{}
	if len(requests) > 0 {
		options = requests[0]
	}
	result, err := scoped.workforceTermination.TerminateIdentityWorkforce(ctx, identitymodel.IdentityWorkforceTerminationMutation{
		WorkspaceID: scoped.IdentityDomainService.WorkspaceID(), Profile: profile, EffectiveAt: strings.TrimSpace(effectiveAt),
		ActorID: strings.TrimSpace(options.ActorID), Reason: strings.TrimSpace(options.Reason),
	})
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, err
	}
	return result.Profile, nil
}

func (s *IdentityApplicationService) ListWorkforceAssignments(ctx context.Context, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return nil, err
	}
	if scoped.workforceRepository == nil {
		return nil, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.IdentityDomainService.WorkspaceID(), profileID)
}

func (s *IdentityApplicationService) UpsertWorkforceAssignment(ctx context.Context, assignment identitymodel.IdentityWorkforceAssignment) error {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return err
	}
	if scoped.WorkforceDomainService == nil {
		return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.WorkforceDomainService.UpsertAssignment(ctx, assignment)
}

func (s *IdentityApplicationService) ValidateWorkforceAssignment(ctx context.Context, assignment identitymodel.IdentityWorkforceAssignment) error {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return err
	}
	if scoped.WorkforceDomainService == nil {
		return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	return scoped.WorkforceDomainService.ValidateAssignment(ctx, assignment)
}

func (s *IdentityApplicationService) workforceForContext(ctx context.Context) (*IdentityApplicationService, error) {
	if _, err := identitymodel.NewWorkspaceID(s.IdentityDomainService.WorkspaceID()); err == nil {
		return s, nil
	}
	workspaceID := requestcontext.WorkspaceID(ctx)
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return nil, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	return s.ForWorkspace(workspaceID)
}

func identityAuthorizeQuery(principal identitymodel.Principal) error {
	if _, err := identitymodel.NewWorkspaceQueryScope(principal.WorkspaceID); !principal.Known || err != nil {
		return &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	return nil
}

func identityWorkforceReadScope(principal identitymodel.Principal) string {
	scope := strings.TrimSpace(identitycontract.IdentityDataScope(principal.Role, "identity_workforce_profile", false))
	if scope == "none" {
		scope = strings.TrimSpace(principal.Role.RecordScope)
	}
	return scope
}

func (s *IdentityApplicationService) canReadWorkforceProfile(ctx context.Context, profile identitymodel.IdentityWorkforceProfile, principal identitymodel.Principal) (bool, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return false, err
	}
	assignments, err := scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.WorkspaceID(), profile.ID)
	if err != nil {
		return false, err
	}
	departments, err := scoped.Repository().ListIdentityDepartments(ctx, scoped.WorkspaceID())
	if err != nil {
		return false, err
	}
	departmentsByID := make(map[string]identitymodel.IdentityDepartment, len(departments))
	for _, department := range departments {
		departmentsByID[department.ID] = department
	}
	return identityWorkforceReadScopeAllows(principal, profile, assignments, departmentsByID), nil
}
