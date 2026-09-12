package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	"golang.org/x/crypto/bcrypt"
)

const IdentityHandlerDeliveryContractVersionV1 = "domainry-identity-handler-delivery-v1"

type IdentityHandlerDeliveryAuthenticator interface {
	VerifyAccessToken(context.Context, string) (authmodel.AuthClaims, error)
	PrincipalFromBearer(context.Context, string, string) (identitymodel.Principal, error)
}

type IdentityHandlerDeliveryApplicationRegistry interface {
	Registered(context.Context, string) (bool, error)
	WorkspaceID() string
}

type IdentityHandlerProfileBindingRequest struct {
	BindingKey      string
	ObjectKey       string
	ProfileID       string
	ExpectedVersion int64
	Reason          string
	ApprovalID      string
}

type IdentityHandlerDeliveryRequest struct {
	ContractVersion string
	AccessToken     string
	IdempotencyKey  string
	Operation       identitymodel.IdentityHandlerUserOperation
	User            identitymodel.IdentityUser
	ExpectedVersion int64
	LoginMode       identitymodel.IdentityHandlerLoginMode
	RoleKeys        []string
	ProfileBinding  *IdentityHandlerProfileBindingRequest
}

type IdentityHandlerBoundIdentityRequest struct {
	ContractVersion string
	AccessToken     string
	UserID          string
	ProfileBinding  *IdentityHandlerProfileBindingSelector
}

type IdentityHandlerProfileBindingSelector struct {
	BindingKey string
	ObjectKey  string
	ProfileID  string
}

type IdentityHandlerBoundIdentity struct {
	UserID                string
	DisplayName           string
	Status                identitymodel.IdentityStatus
	Active                bool
	Version               int64
	OrganizationID        string
	OrganizationPath      string
	OrganizationScopeIDs  []string
	SupportOrganizationID string
	SupportOrgScopeIDs    []string
	ManagerUserID         string
	ReportingPath         string
	ReportingScopeUserIDs []string
	RoleKeys              []string
	ProfileBinding        *identitymodel.IdentityProfileBinding
}

type IdentityHandlerDeliveryDependencies struct {
	WorkspaceID     string
	Authentication  IdentityHandlerDeliveryAuthenticator
	Applications    IdentityHandlerDeliveryApplicationRegistry
	Identity        *IdentityApplicationService
	ProfileBindings *IdentityProfileBindingApplicationService
	Transactions    identityrepository.IdentityTransactionManager
	Repository      identityrepository.IdentityHandlerDeliveryRepository
	Audit           auditapplication.AuditAppender
}

type IdentityHandlerDeliveryApplicationService struct {
	dependencies IdentityHandlerDeliveryDependencies
}

func NewIdentityHandlerDeliveryApplicationService(dependencies IdentityHandlerDeliveryDependencies) *IdentityHandlerDeliveryApplicationService {
	return &IdentityHandlerDeliveryApplicationService{dependencies: dependencies}
}

func (s *IdentityApplicationService) PrepareUserForAtomicDelivery(ctx context.Context, user identitymodel.IdentityUser) (identitymodel.IdentityUser, []identitymodel.IdentityUser, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, nil, err
	}
	return scoped.PrepareUserForAtomicDelivery(ctx, user)
}

func (s *IdentityApplicationService) PrepareUserWithExactRoles(ctx context.Context, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment, actor identitymodel.Principal) (identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, nil, err
	}
	return scoped.PrepareUserWithExactRoles(ctx, user, assignments, actor)
}

func (s *IdentityHandlerDeliveryApplicationService) ResolveBoundIdentity(ctx context.Context, request IdentityHandlerBoundIdentityRequest) (IdentityHandlerBoundIdentity, error) {
	if err := ctx.Err(); err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	if s == nil || s.dependencies.Authentication == nil || s.dependencies.Applications == nil || s.dependencies.Identity == nil {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindInternal, "backend.identity.handler_delivery_unavailable")
	}
	request.ContractVersion, request.AccessToken, request.UserID = strings.TrimSpace(request.ContractVersion), strings.TrimSpace(request.AccessToken), strings.TrimSpace(request.UserID)
	if request.ContractVersion != IdentityHandlerDeliveryContractVersionV1 || request.AccessToken == "" || request.UserID == "" {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_projection_invalid")
	}
	if request.ProfileBinding != nil {
		request.ProfileBinding.BindingKey = strings.TrimSpace(request.ProfileBinding.BindingKey)
		request.ProfileBinding.ObjectKey = strings.TrimSpace(request.ProfileBinding.ObjectKey)
		request.ProfileBinding.ProfileID = strings.TrimSpace(request.ProfileBinding.ProfileID)
		if request.ProfileBinding.BindingKey == "" || request.ProfileBinding.ObjectKey == "" || request.ProfileBinding.ProfileID == "" {
			return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_projection_invalid")
		}
	}
	claims, err := s.dependencies.Authentication.VerifyAccessToken(ctx, request.AccessToken)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	workspaceID := strings.TrimSpace(s.dependencies.WorkspaceID)
	registered, err := s.dependencies.Applications.Registered(ctx, claims.Audience)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	if claims.WorkspaceID != workspaceID || s.dependencies.Applications.WorkspaceID() != workspaceID || !registered {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindForbidden, "identity.handler_delivery_application_scope_mismatch")
	}
	workspaceContext := requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal, err := s.dependencies.Authentication.PrincipalFromBearer(workspaceContext, "Bearer "+request.AccessToken, requestcontext.RequestID(ctx))
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	if !principal.Known || principal.UserID != claims.Subject || principal.WorkspaceID != workspaceID || principal.AuthorizationRevision == "" || principal.AuthorizationRevision != claims.AuthorizationRevision {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindConflict, "auth.authorization_stale")
	}
	permissionKey := identitycontract.IdentityHandlerDeliveryResolvePermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindForbidden, "backend.identity.handler_projection_denied")
	}
	user, found, err := s.dependencies.Identity.UserByIDWithinDataScope(workspaceContext, request.UserID, principal, permissionKey)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	if !found {
		return IdentityHandlerBoundIdentity{}, handlerDeliveryError(apperror.KindForbidden, "backend.identity.handler_projection_denied")
	}
	assignments, err := s.dependencies.Identity.ListUserRoleAssignmentsWithinDataScope(workspaceContext, request.UserID, principal, permissionKey)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	roles, err := s.dependencies.Identity.ListRoles(workspaceContext)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	roleKeyByID := make(map[string]string, len(roles))
	for _, role := range roles {
		if role.Status == identitymodel.IdentityStatusActive {
			roleKeyByID[role.ID] = role.Key
		}
	}
	roleKeys := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		if strings.TrimSpace(assignment.Status) != "active" {
			continue
		}
		if roleKey := strings.TrimSpace(roleKeyByID[assignment.RoleID]); roleKey != "" {
			roleKeys = append(roleKeys, roleKey)
		}
	}
	roleKeys, _ = canonicalHandlerRoleKeys(roleKeys)
	targetPrincipal := identitymodel.Principal{}
	if user.Status == identitymodel.IdentityStatusActive {
		targetPrincipal, err = s.dependencies.Identity.ResolvePrincipal(workspaceContext, user.ID)
		if err != nil {
			return IdentityHandlerBoundIdentity{}, err
		}
	}
	profileBinding, err := s.resolveRequestedProfileBinding(workspaceContext, workspaceID, user.ID, request.ProfileBinding)
	if err != nil {
		return IdentityHandlerBoundIdentity{}, err
	}
	return IdentityHandlerBoundIdentity{
		UserID: user.ID, DisplayName: user.Name, Status: user.Status, Active: user.Status == identitymodel.IdentityStatusActive,
		Version: user.Version, OrganizationID: user.OrgID, SupportOrganizationID: user.SupportOrgID,
		OrganizationPath: targetPrincipal.OrganizationPath, OrganizationScopeIDs: append([]string(nil), targetPrincipal.OrgScopeIDs...),
		SupportOrgScopeIDs: append([]string(nil), targetPrincipal.SupportOrgScopeIDs...), ManagerUserID: user.ManagerUserID,
		ReportingPath: user.ReportingPath, ReportingScopeUserIDs: append([]string(nil), targetPrincipal.ReportingScopeUserIDs...), RoleKeys: roleKeys,
		ProfileBinding: profileBinding,
	}, nil
}

func (s *IdentityHandlerDeliveryApplicationService) resolveRequestedProfileBinding(ctx context.Context, workspaceID, userID string, selector *IdentityHandlerProfileBindingSelector) (*identitymodel.IdentityProfileBinding, error) {
	if selector == nil {
		return nil, nil
	}
	if s == nil || s.dependencies.ProfileBindings == nil {
		return nil, handlerDeliveryError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	if _, _, published := s.dependencies.ProfileBindings.profileBindingDefinition(selector.ObjectKey, selector.BindingKey); !published {
		return nil, handlerDeliveryError(apperror.KindForbidden, "backend.identity.handler_projection_denied")
	}
	binding, found, err := s.dependencies.ProfileBindings.CurrentBinding(ctx, workspaceID, selector.ObjectKey, selector.ProfileID)
	if err != nil {
		return nil, err
	}
	if !found || strings.TrimSpace(binding.BindingKey) != selector.BindingKey || strings.TrimSpace(binding.ObjectKey) != selector.ObjectKey ||
		strings.TrimSpace(binding.ProfileID) != selector.ProfileID || strings.TrimSpace(binding.IdentityUserID) != strings.TrimSpace(userID) ||
		binding.Status != identitymodel.IdentityProfileBindingActive || binding.Version < 1 {
		return nil, handlerDeliveryError(apperror.KindForbidden, "backend.identity.handler_projection_denied")
	}
	bindingCopy := binding
	return &bindingCopy, nil
}

func (s *IdentityHandlerDeliveryApplicationService) Deliver(ctx context.Context, request IdentityHandlerDeliveryRequest) (identitymodel.IdentityHandlerDeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	if s == nil || s.dependencies.Authentication == nil || s.dependencies.Applications == nil || s.dependencies.Identity == nil || s.dependencies.Transactions == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindInternal, "backend.identity.handler_delivery_unavailable")
	}
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	if request.ContractVersion != IdentityHandlerDeliveryContractVersionV1 || request.IdempotencyKey == "" || request.AccessToken == "" || request.ExpectedVersion < 0 || strings.TrimSpace(request.User.ID) == "" {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_delivery_invalid")
	}
	if request.Operation != identitymodel.IdentityHandlerUserCreate && request.Operation != identitymodel.IdentityHandlerUserUpdate && request.Operation != identitymodel.IdentityHandlerUserDisable {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_delivery_operation_invalid")
	}
	if request.Operation == identitymodel.IdentityHandlerUserCreate {
		if request.LoginMode != identitymodel.IdentityHandlerLoginNone && request.LoginMode != identitymodel.IdentityHandlerLoginPassword {
			return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_delivery_login_mode_invalid")
		}
	} else if request.LoginMode != "" {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.handler_delivery_login_mode_invalid")
	}
	claims, err := s.dependencies.Authentication.VerifyAccessToken(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	workspaceID := strings.TrimSpace(s.dependencies.WorkspaceID)
	if claims.WorkspaceID != workspaceID || s.dependencies.Applications.WorkspaceID() != workspaceID {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindForbidden, "auth.workspace_mismatch")
	}
	registered, err := s.dependencies.Applications.Registered(ctx, claims.Audience)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	if !registered {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindForbidden, "identity.application_not_registered")
	}
	workspaceContext := requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal, err := s.dependencies.Authentication.PrincipalFromBearer(workspaceContext, "Bearer "+request.AccessToken, requestcontext.RequestID(ctx))
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	if !principal.Known || principal.WorkspaceID != workspaceID || principal.UserID != claims.Subject {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindForbidden, "backend.identity.handler_delivery_actor_invalid")
	}
	if principal.AuthorizationRevision == "" || principal.AuthorizationRevision != claims.AuthorizationRevision {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindConflict, "auth.authorization_stale")
	}
	permissionKey := handlerDeliveryPermissionForOperation(request.Operation)
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityHandlerDeliveryResult{}, handlerDeliveryError(apperror.KindForbidden, "backend.identity.data_scope_denied")
	}

	request.RoleKeys, err = canonicalHandlerRoleKeys(request.RoleKeys)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	request.User.ID = strings.TrimSpace(request.User.ID)
	fingerprint, err := identityHandlerDeliveryFingerprint(request, principal.UserID, claims.Audience)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	var result identitymodel.IdentityHandlerDeliveryResult
	initialPassword := ""
	err = s.dependencies.Transactions.WithinIdentityTransaction(workspaceContext, func(transactionContext context.Context) error {
		if receipt, found, loadErr := s.dependencies.Repository.GetIdentityHandlerDeliveryReceipt(transactionContext, workspaceID, request.IdempotencyKey); loadErr != nil {
			return loadErr
		} else if found {
			if receipt.RequestFingerprint != fingerprint {
				return handlerDeliveryError(apperror.KindConflict, "backend.idempotency_key_reused")
			}
			current, currentFound, currentErr := s.dependencies.Identity.FindUser(transactionContext, request.User.ID)
			if currentErr != nil {
				return currentErr
			}
			if !currentFound {
				current = receipt.Result.User
			}
			if !handlerDeliveryScopeAllows(principal, permissionKey, current, receipt.Result.User, true) {
				return handlerDeliveryError(apperror.KindForbidden, "backend.identity.data_scope_denied")
			}
			result = receipt.Result
			result.Replayed = true
			return nil
		}

		mutation, before, password, prepareErr := s.prepareMutation(transactionContext, request, principal, fingerprint)
		if prepareErr != nil {
			return fmt.Errorf("prepare Identity handler delivery: %w", prepareErr)
		}
		initialPassword = password
		receipt, executeErr := s.dependencies.Repository.ExecuteIdentityHandlerDelivery(transactionContext, mutation)
		if executeErr != nil {
			return fmt.Errorf("persist Identity handler delivery: %w", executeErr)
		}
		if err := s.dependencies.Audit.AppendAudit(transactionContext, auditapplication.AuditAppendRequest{
			IdempotencyKey: "identity-handler-delivery:" + request.IdempotencyKey,
			Event:          "identity.handler_delivery." + string(request.Operation), ObjectKey: identitycontract.IdentityUserObjectKey,
			RecordID: request.User.ID, Principal: principal, Summary: "Runtime handler delivered Identity state",
			Before: handlerDeliveryUserAuditMap(before), After: handlerDeliveryUserAuditMap(receipt.Result.User),
			Metadata: map[string]any{"application_key": claims.Audience, "idempotency_key": request.IdempotencyKey, "role_keys": append([]string(nil), request.RoleKeys...), "profile_binding": request.ProfileBinding != nil, "login_mode": request.LoginMode},
		}); err != nil {
			return fmt.Errorf("append Identity handler delivery audit: %w", err)
		}
		result = receipt.Result
		return nil
	})
	if err == nil && initialPassword != "" && !result.Replayed {
		result.InitialPassword = initialPassword
		result.MustChangePassword = true
		result.NoStore = true
	}
	return result, err
}

func (s *IdentityHandlerDeliveryApplicationService) prepareMutation(ctx context.Context, request IdentityHandlerDeliveryRequest, principal identitymodel.Principal, fingerprint string) (identitymodel.IdentityHandlerDeliveryMutation, identitymodel.IdentityUser, string, error) {
	current, found, err := s.dependencies.Identity.FindUser(ctx, request.User.ID)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryMutation{}, identitymodel.IdentityUser{}, "", err
	}
	permissionKey := handlerDeliveryPermissionForOperation(request.Operation)
	switch request.Operation {
	case identitymodel.IdentityHandlerUserCreate:
		if request.ExpectedVersion != 0 || found {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindConflict, "backend.identity.user_version_conflict")
		}
	case identitymodel.IdentityHandlerUserUpdate:
		if !found {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindNotFound, "backend.identity.user_not_found")
		}
	case identitymodel.IdentityHandlerUserDisable:
		if !found {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindNotFound, "backend.identity.user_not_found")
		}
	}
	if found && (request.ExpectedVersion < 1 || current.Version != request.ExpectedVersion) {
		return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindConflict, "backend.identity.user_version_conflict")
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) || !handlerDeliveryScopeAllows(principal, permissionKey, current, request.User, found) {
		return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindForbidden, "backend.identity.data_scope_denied")
	}
	desired := request.User
	if request.Operation == identitymodel.IdentityHandlerUserDisable {
		desired = current
		desired.Status = identitymodel.IdentityStatusDisabled
	} else if found {
		desired.Version = current.Version
		desired.CreatedAt = current.CreatedAt
	}
	prepared, related, err := s.dependencies.Identity.PrepareUserForAtomicDelivery(ctx, desired)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", err
	}
	roles, err := s.dependencies.Identity.ListRoles(ctx)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", err
	}
	roleIDs := make(map[string]string, len(roles))
	for _, role := range roles {
		if role.Status == identitymodel.IdentityStatusActive {
			roleIDs[strings.TrimSpace(role.Key)] = role.ID
		}
	}
	assignments := make([]identitymodel.IdentityUserRoleAssignment, 0, len(request.RoleKeys))
	for _, roleKey := range request.RoleKeys {
		roleID := strings.TrimSpace(roleIDs[roleKey])
		if roleID == "" {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindBadRequest, "backend.identity.role_not_found")
		}
		assignments = append(assignments, identitymodel.IdentityUserRoleAssignment{UserID: prepared.ID, RoleID: roleID})
	}
	prepared, assignments, err = s.dependencies.Identity.PrepareUserWithExactRoles(ctx, prepared, assignments, principal)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", err
	}

	mutation := identitymodel.IdentityHandlerDeliveryMutation{
		WorkspaceID: principal.WorkspaceID, ActorID: principal.UserID, IdempotencyKey: request.IdempotencyKey,
		RequestFingerprint: fingerprint, Operation: request.Operation, User: prepared, RelatedUserUpdates: related,
		ExpectedVersion: request.ExpectedVersion, DataScope: identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
		RoleAssignments: assignments, RoleKeys: append([]string(nil), request.RoleKeys...),
	}
	if request.Operation == identitymodel.IdentityHandlerUserDisable {
		mutation.RevokeUserIDs = append(mutation.RevokeUserIDs, prepared.ID)
	}
	initialPassword := ""
	if request.Operation == identitymodel.IdentityHandlerUserCreate && request.LoginMode == identitymodel.IdentityHandlerLoginPassword {
		initialPassword, err = generateHandlerInitialPassword()
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", err
		}
		passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
		if hashErr != nil {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", hashErr
		}
		mutation.Credential = &identitymodel.IdentityCredential{UserID: prepared.ID, PasswordHash: string(passwordHash), MustChangePassword: true}
	}
	if request.ProfileBinding != nil {
		if s.dependencies.ProfileBindings == nil {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
		}
		profile := request.ProfileBinding
		currentBinding, bindingFound, loadErr := s.dependencies.ProfileBindings.CurrentBinding(ctx, principal.WorkspaceID, profile.ObjectKey, profile.ProfileID)
		if loadErr != nil {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", loadErr
		}
		if bindingFound && currentBinding.Version != profile.ExpectedVersion {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindConflict, "backend.identity.profile_binding_version_conflict")
		}
		if !bindingFound && profile.ExpectedVersion != 0 {
			return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", handlerDeliveryError(apperror.KindConflict, "backend.identity.profile_binding_version_conflict")
		}
		if !(bindingFound && currentBinding.Status == identitymodel.IdentityProfileBindingActive && currentBinding.IdentityUserID == prepared.ID) {
			operation := identitymodel.IdentityProfileBindingBind
			if bindingFound && strings.TrimSpace(currentBinding.IdentityUserID) != "" {
				operation = identitymodel.IdentityProfileBindingRebind
				mutation.RevokeUserIDs = append(mutation.RevokeUserIDs, currentBinding.IdentityUserID)
			}
			preparedProfile, _, prepareErr := s.dependencies.ProfileBindings.PrepareMutationForAtomicDelivery(ctx, IdentityProfileBindingCommandRequest{
				ObjectKey: strings.TrimSpace(profile.ObjectKey), ProfileID: strings.TrimSpace(profile.ProfileID), BindingKey: strings.TrimSpace(profile.BindingKey),
				Operation: string(operation), IdentityUserID: prepared.ID, ExpectedVersion: profile.ExpectedVersion,
				IdempotencyKey: request.IdempotencyKey + ":profile", Reason: strings.TrimSpace(profile.Reason), ApprovalID: strings.TrimSpace(profile.ApprovalID),
			}, principal, prepared, permissionKey)
			if prepareErr != nil {
				return identitymodel.IdentityHandlerDeliveryMutation{}, current, "", prepareErr
			}
			mutation.ProfileBinding = &preparedProfile
		} else {
			mutation.ProfileBindingResult = &currentBinding
		}
	}
	return mutation, current, initialPassword, nil
}

func handlerDeliveryPermissionForOperation(operation identitymodel.IdentityHandlerUserOperation) string {
	switch operation {
	case identitymodel.IdentityHandlerUserCreate:
		return identitycontract.IdentityHandlerDeliveryCreatePermission
	case identitymodel.IdentityHandlerUserUpdate:
		return identitycontract.IdentityHandlerDeliveryUpdatePermission
	case identitymodel.IdentityHandlerUserDisable:
		return identitycontract.IdentityHandlerDeliveryDisablePermission
	default:
		return ""
	}
}

func generateHandlerInitialPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-"
	bytes := make([]byte, 28)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	password := []byte("Aa1!")
	for _, value := range bytes {
		password = append(password, alphabet[int(value)%len(alphabet)])
	}
	return string(password), nil
}

func handlerDeliveryScopeAllows(principal identitymodel.Principal, permissionKey string, current, desired identitymodel.IdentityUser, currentFound bool) bool {
	if currentFound && !identitycontract.IdentityPermissionDataScopeAllows(principal, permissionKey, identitycontract.IdentityResourceFacts{RecordID: current.ID, OwnerUserID: current.ID, OwnerOrgID: current.OrgID}) {
		return false
	}
	return identitycontract.IdentityPermissionDataScopeAllows(principal, permissionKey, identitycontract.IdentityResourceFacts{RecordID: desired.ID, OwnerUserID: desired.ID, OwnerOrgID: desired.OrgID})
}

func canonicalHandlerRoleKeys(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, handlerDeliveryError(apperror.KindBadRequest, "backend.identity.role_required")
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slicesSort(out)
	return out, nil
}

func slicesSort(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

func identityHandlerDeliveryFingerprint(request IdentityHandlerDeliveryRequest, actorID, audience string) (string, error) {
	request.AccessToken = ""
	payload, err := json.Marshal(struct {
		Request  IdentityHandlerDeliveryRequest `json:"request"`
		ActorID  string                         `json:"actor_id"`
		Audience string                         `json:"audience"`
	}{Request: request, ActorID: actorID, Audience: audience})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func handlerDeliveryUserAuditMap(user identitymodel.IdentityUser) map[string]any {
	if strings.TrimSpace(user.ID) == "" {
		return nil
	}
	return map[string]any{"id": user.ID, "status": user.Status, "org_id": user.OrgID, "support_org_id": user.SupportOrgID, "version": user.Version}
}

func handlerDeliveryError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

// ForWorkspace returns an immutable host-authorized view; callers supply the
// matching source-owned application registry after token verification.
func (s *IdentityHandlerDeliveryApplicationService) ForWorkspace(workspaceID string, applications IdentityHandlerDeliveryApplicationRegistry) *IdentityHandlerDeliveryApplicationService {
	clone := *s
	clone.dependencies.WorkspaceID = workspaceID
	clone.dependencies.Applications = applications
	return &clone
}
