package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	auditcontract "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

const IdentityOrganizationUnitDeliveryContractVersionV1 = "domainry-identity-organization-unit-delivery-v1"

type IdentityOrganizationUnitDeliveryRequest struct {
	ContractVersion      string
	AccessToken          string
	IdempotencyKey       string
	OrganizationID       string
	Code                 string
	Name                 string
	NodeType             identitymodel.IdentityOrganizationUnitType
	ParentOrganizationID string
	SortOrder            int
	ExpectedVersion      int64
}

type IdentityOrganizationUnitResolveRequest struct {
	ContractVersion string
	AccessToken     string
	OrganizationID  string
	NodeType        identitymodel.IdentityOrganizationUnitType
}

type IdentityOrganizationUnitDeliveryDependencies struct {
	WorkspaceID    string
	Authentication IdentityHandlerDeliveryAuthenticator
	Applications   IdentityHandlerDeliveryApplicationRegistry
	Identity       *IdentityApplicationService
	Transactions   identityrepository.IdentityTransactionManager
	Repository     identityrepository.IdentityOrganizationUnitDeliveryRepository
	Audit          auditapplication.AuditAppender
}

type IdentityOrganizationUnitDeliveryApplicationService struct {
	dependencies IdentityOrganizationUnitDeliveryDependencies
}

func NewIdentityOrganizationUnitDeliveryApplicationService(dependencies IdentityOrganizationUnitDeliveryDependencies) *IdentityOrganizationUnitDeliveryApplicationService {
	return &IdentityOrganizationUnitDeliveryApplicationService{dependencies: dependencies}
}

func (s *IdentityOrganizationUnitDeliveryApplicationService) Create(ctx context.Context, request IdentityOrganizationUnitDeliveryRequest) (identitymodel.IdentityOrganizationUnitDeliveryResult, error) {
	if s == nil || s.dependencies.Identity == nil || s.dependencies.Transactions == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindInternal, "backend.identity.organization_unit_delivery_unavailable")
	}
	normalizeIdentityOrganizationUnitDeliveryRequest(&request)
	if err := validateIdentityOrganizationUnitDeliveryRequest(request); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, err
	}
	workspaceContext, claims, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, err
	}
	permissionKey := identitycontract.IdentityOrganizationUnitDeliveryCreatePermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) || !organizationUnitParentScopeAllows(principal, permissionKey, request.ParentOrganizationID) {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_scope_denied")
	}
	fingerprint, err := identityOrganizationUnitDeliveryRequestFingerprint(request, principal.UserID, claims.Audience)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, err
	}
	var result identitymodel.IdentityOrganizationUnitDeliveryResult
	err = s.dependencies.Transactions.WithinIdentityTransaction(workspaceContext, func(transactionContext context.Context) error {
		parent, parentFound, lockErr := s.dependencies.Repository.LockIdentityOrganizationUnitDeliveryParent(transactionContext, principal.WorkspaceID, request.ParentOrganizationID)
		if lockErr != nil {
			return lockErr
		}
		if receipt, found, loadErr := s.dependencies.Repository.GetIdentityOrganizationUnitDeliveryReceipt(transactionContext, principal.WorkspaceID, request.IdempotencyKey); loadErr != nil {
			return loadErr
		} else if found {
			if receipt.RequestFingerprint != fingerprint {
				return organizationUnitDeliveryError(apperror.KindConflict, "backend.idempotency_key_reused")
			}
			if replayErr := s.authorizeReplay(transactionContext, request, receipt, principal, permissionKey); replayErr != nil {
				return replayErr
			}
			result = receipt.Result
			result.Replayed = true
			return nil
		}

		if !validOrganizationUnitDeliveryParent(parent, parentFound) {
			return organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_parent_invalid")
		}
		if _, found, loadErr := s.dependencies.Identity.FindOrganizationUnit(transactionContext, request.OrganizationID); loadErr != nil {
			return loadErr
		} else if found {
			return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}

		parentID := request.ParentOrganizationID
		prepared, related, prepareErr := s.dependencies.Identity.PrepareOrganizationUnitForAtomicDelivery(transactionContext, identitymodel.IdentityOrganizationUnit{
			ID: request.OrganizationID, Code: request.Code, Name: request.Name, NodeType: request.NodeType,
			ParentID: &parentID, SortOrder: request.SortOrder, Status: identitymodel.IdentityStatusActive,
		})
		if prepareErr != nil {
			return fmt.Errorf("prepare Identity organization unit delivery: %w", prepareErr)
		}
		if len(related) != 0 || identityOrganizationUnitParentID(prepared.ParentID) != request.ParentOrganizationID || prepared.NodeType != request.NodeType || prepared.Status != identitymodel.IdentityStatusActive {
			return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		mutation := identitymodel.IdentityOrganizationUnitDeliveryMutation{
			WorkspaceID: principal.WorkspaceID, ActorID: principal.UserID, IdempotencyKey: request.IdempotencyKey,
			RequestFingerprint: fingerprint, Organization: prepared, ExpectedVersion: request.ExpectedVersion,
			DataScope: identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
		}
		receipt, executeErr := s.dependencies.Repository.ExecuteIdentityOrganizationUnitDelivery(transactionContext, mutation)
		if executeErr != nil {
			return fmt.Errorf("persist Identity organization unit delivery: %w", executeErr)
		}
		if appendErr := s.dependencies.Audit.AppendAudit(transactionContext, auditapplication.AuditAppendRequest{
			IdempotencyKey: "identity-organization-unit-delivery:" + request.IdempotencyKey,
			Family:         auditcontract.EventFamilyIdentityGovernance,
			Event:          "identity.organization_unit_delivery.create",
			ObjectKey:      identitycontract.IdentityOrganizationUnitObjectKey,
			RecordID:       request.OrganizationID,
			Principal:      principal,
			Summary:        "Runtime handler created an Identity organization unit",
			After:          organizationUnitDeliveryAuditMap(receipt.Result.Organization),
			Metadata: map[string]any{
				"application_key": claims.Audience, "idempotency_key": request.IdempotencyKey,
			},
		}); appendErr != nil {
			return fmt.Errorf("append Identity organization unit delivery audit: %w", appendErr)
		}
		result = receipt.Result
		return nil
	})
	return result, err
}

func (s *IdentityOrganizationUnitDeliveryApplicationService) Resolve(ctx context.Context, request IdentityOrganizationUnitResolveRequest) (identitymodel.IdentityDeliveredOrganizationUnit, error) {
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	request.OrganizationID = strings.TrimSpace(request.OrganizationID)
	if request.ContractVersion != IdentityOrganizationUnitDeliveryContractVersionV1 || request.AccessToken == "" || request.OrganizationID == "" || !validDeliveredOrganizationUnitType(request.NodeType) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_projection_invalid")
	}
	workspaceContext, _, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, err
	}
	permissionKey := identitycontract.IdentityOrganizationUnitDeliveryResolvePermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_projection_denied")
	}
	organization, found, err := s.dependencies.Repository.ResolveIdentityDeliveredOrganizationUnit(
		workspaceContext, principal.WorkspaceID, request.OrganizationID, request.NodeType,
		identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
	)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, err
	}
	if !found {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_projection_denied")
	}
	return organization, nil
}

func (s *IdentityOrganizationUnitDeliveryApplicationService) authorizeReplay(ctx context.Context, request IdentityOrganizationUnitDeliveryRequest, receipt identitymodel.IdentityOrganizationUnitDeliveryReceipt, principal identitymodel.Principal, permissionKey string) error {
	receipted := receipt.Result.Organization
	if receipted.ID != request.OrganizationID || receipted.Code != request.Code || receipted.Name != request.Name || receipted.NodeType != request.NodeType ||
		receipted.ParentOrganizationID != request.ParentOrganizationID || receipted.SortOrder != request.SortOrder || receipted.Status != string(identitymodel.IdentityStatusActive) || receipted.Version != 1 {
		return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	if !organizationUnitParentScopeAllows(principal, permissionKey, request.ParentOrganizationID) {
		return organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_scope_denied")
	}
	parent, parentFound, err := s.dependencies.Identity.FindOrganizationUnit(ctx, request.ParentOrganizationID)
	if err != nil {
		return err
	}
	if !validOrganizationUnitDeliveryParent(parent, parentFound) {
		return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	current, found, err := s.dependencies.Identity.FindOrganizationUnit(ctx, request.OrganizationID)
	if err != nil {
		return err
	}
	if !found || identityOrganizationUnitParentID(current.ParentID) != request.ParentOrganizationID || current.NodeType != request.NodeType || identityOrganizationUnitDeliveryFingerprint(current) != identityDeliveredOrganizationUnitFingerprint(receipted) {
		return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	state, found, err := s.dependencies.Repository.GetIdentityOrganizationUnitDeliveryState(ctx, principal.WorkspaceID, request.OrganizationID)
	if err != nil {
		return err
	}
	if !found || state.Version != 1 || state.StateFingerprint != identityOrganizationUnitDeliveryFingerprint(current) {
		return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	return nil
}

func (s *IdentityOrganizationUnitDeliveryApplicationService) authorize(ctx context.Context, accessToken string) (context.Context, authmodel.AuthClaims, identitymodel.Principal, error) {
	if err := ctx.Err(); err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	if s == nil || s.dependencies.Authentication == nil || s.dependencies.Applications == nil || s.dependencies.Identity == nil || s.dependencies.Repository == nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, organizationUnitDeliveryError(apperror.KindInternal, "backend.identity.organization_unit_delivery_unavailable")
	}
	claims, err := s.dependencies.Authentication.VerifyAccessToken(ctx, strings.TrimSpace(accessToken))
	if err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	workspaceID := strings.TrimSpace(s.dependencies.WorkspaceID)
	registered, err := s.dependencies.Applications.Registered(ctx, claims.Audience)
	if err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	if claims.WorkspaceID != workspaceID || s.dependencies.Applications.WorkspaceID() != workspaceID || !registered {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, organizationUnitDeliveryError(apperror.KindForbidden, "identity.organization_unit_delivery_application_scope_mismatch")
	}
	workspaceContext := requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal, err := s.dependencies.Authentication.PrincipalFromBearer(workspaceContext, "Bearer "+accessToken, requestcontext.RequestID(ctx))
	if err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	if !principal.Known || principal.UserID != claims.Subject || principal.WorkspaceID != workspaceID {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_actor_invalid")
	}
	if principal.AuthorizationRevision == "" || principal.AuthorizationRevision != claims.AuthorizationRevision {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, organizationUnitDeliveryError(apperror.KindConflict, "auth.authorization_stale")
	}
	return workspaceContext, claims, principal, nil
}

func normalizeIdentityOrganizationUnitDeliveryRequest(request *IdentityOrganizationUnitDeliveryRequest) {
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.OrganizationID = strings.TrimSpace(request.OrganizationID)
	request.Code = strings.TrimSpace(request.Code)
	request.Name = strings.TrimSpace(request.Name)
	request.ParentOrganizationID = strings.TrimSpace(request.ParentOrganizationID)
}

func validateIdentityOrganizationUnitDeliveryRequest(request IdentityOrganizationUnitDeliveryRequest) error {
	if request.ContractVersion != IdentityOrganizationUnitDeliveryContractVersionV1 || request.AccessToken == "" || request.IdempotencyKey == "" || request.OrganizationID == "" || request.Code == "" || request.Name == "" || request.ParentOrganizationID == "" || request.ExpectedVersion != 0 || request.SortOrder < 0 {
		return organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
	}
	if !validDeliveredOrganizationUnitType(request.NodeType) {
		return organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_type_invalid")
	}
	return nil
}

func validDeliveredOrganizationUnitType(nodeType identitymodel.IdentityOrganizationUnitType) bool {
	switch nodeType {
	case identitymodel.IdentityOrganizationUnitRegion, identitymodel.IdentityOrganizationUnitDepartment, identitymodel.IdentityOrganizationUnitTeam, identitymodel.IdentityOrganizationUnitWarehouse:
		return true
	default:
		return false
	}
}

func validOrganizationUnitDeliveryParent(parent identitymodel.IdentityOrganizationUnit, found bool) bool {
	return found && strings.TrimSpace(parent.ID) != "" && parent.NodeType.Valid() && parent.Status == identitymodel.IdentityStatusActive
}

func organizationUnitParentScopeAllows(principal identitymodel.Principal, permissionKey, parentID string) bool {
	return identitycontract.IdentityPermissionDataScopeAllows(principal, permissionKey, identitycontract.IdentityResourceFacts{RecordID: parentID, OwnerOrgID: parentID})
}

func identityOrganizationUnitDeliveryRequestFingerprint(request IdentityOrganizationUnitDeliveryRequest, actorID, audience string) (string, error) {
	request.AccessToken = ""
	payload, err := json.Marshal(struct {
		Request  IdentityOrganizationUnitDeliveryRequest `json:"request"`
		ActorID  string                                  `json:"actor_id"`
		Audience string                                  `json:"audience"`
	}{Request: request, ActorID: actorID, Audience: audience})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func identityOrganizationUnitDeliveryFingerprint(organization identitymodel.IdentityOrganizationUnit) string {
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func identityDeliveredOrganizationUnitFingerprint(organization identitymodel.IdentityDeliveredOrganizationUnit) string {
	parentID := organization.ParentOrganizationID
	return identityOrganizationUnitDeliveryFingerprint(identitymodel.IdentityOrganizationUnit{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		ParentID: &parentID, Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...),
		Depth: organization.Depth, SortOrder: organization.SortOrder, Status: identitymodel.IdentityStatus(organization.Status),
	})
}

func identityOrganizationUnitParentID(parentID *string) string {
	if parentID == nil {
		return ""
	}
	return strings.TrimSpace(*parentID)
}

func identityOrganizationUnitDeliveryProjection(organization identitymodel.IdentityOrganizationUnit, version int64) identitymodel.IdentityDeliveredOrganizationUnit {
	return identitymodel.IdentityDeliveredOrganizationUnit{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		Status: string(organization.Status), ParentOrganizationID: identityOrganizationUnitParentID(organization.ParentID),
		Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...), Depth: organization.Depth,
		SortOrder: organization.SortOrder, Version: version,
	}
}

func organizationUnitDeliveryAuditMap(organization identitymodel.IdentityDeliveredOrganizationUnit) map[string]any {
	return map[string]any{
		"id": organization.ID, "code": organization.Code, "name": organization.Name, "node_type": organization.NodeType,
		"status": organization.Status, "parent_id": organization.ParentOrganizationID, "version": organization.Version,
	}
}

func organizationUnitDeliveryError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

// ForWorkspace returns an immutable host-authorized view; callers supply the
// matching source-owned application registry after token verification.
func (s *IdentityOrganizationUnitDeliveryApplicationService) ForWorkspace(workspaceID string, applications IdentityHandlerDeliveryApplicationRegistry) *IdentityOrganizationUnitDeliveryApplicationService {
	clone := *s
	clone.dependencies.WorkspaceID = workspaceID
	clone.dependencies.Applications = applications
	return &clone
}
