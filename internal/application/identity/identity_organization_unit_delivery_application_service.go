package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

const (
	IdentityOrganizationUnitDefaultPageSize = 50
	IdentityOrganizationUnitMaxPageSize     = 100
)

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

type IdentityOrganizationUnitMutationRequest struct {
	ContractVersion string
	AccessToken     string
	IdempotencyKey  string
	Operation       identitymodel.IdentityOrganizationUnitOperation
	OrganizationID  string
	NodeType        identitymodel.IdentityOrganizationUnitType
	Name            string
	ExpectedVersion int64
}

type IdentityOrganizationUnitListRequest struct {
	ContractVersion string
	AccessToken     string
	NodeType        identitymodel.IdentityOrganizationUnitType
	PageSize        int
	Cursor          string
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
			OrganizationUnitID: request.OrganizationID, Code: request.Code, Name: request.Name, NodeType: request.NodeType,
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
			RequestFingerprint: fingerprint, Operation: identitymodel.IdentityOrganizationUnitCreate, Organization: prepared, ExpectedVersion: request.ExpectedVersion,
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

func (s *IdentityOrganizationUnitDeliveryApplicationService) Mutate(ctx context.Context, request IdentityOrganizationUnitMutationRequest) (identitymodel.IdentityOrganizationUnitDeliveryResult, error) {
	if s == nil || s.dependencies.Identity == nil || s.dependencies.Transactions == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindInternal, "backend.identity.organization_unit_delivery_unavailable")
	}
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.OrganizationID = strings.TrimSpace(request.OrganizationID)
	request.Name = strings.TrimSpace(request.Name)
	if request.ContractVersion != IdentityOrganizationUnitDeliveryContractVersionV1 || request.AccessToken == "" || request.IdempotencyKey == "" || request.OrganizationID == "" || !validDeliveredOrganizationUnitType(request.NodeType) || request.ExpectedVersion < 1 {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
	}
	permissionKey := ""
	switch request.Operation {
	case identitymodel.IdentityOrganizationUnitRename:
		if request.Name == "" {
			return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
		}
		permissionKey = identitycontract.IdentityOrganizationUnitDeliveryRenamePermission
	case identitymodel.IdentityOrganizationUnitDisable:
		if request.Name != "" {
			return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
		}
		permissionKey = identitycontract.IdentityOrganizationUnitDeliveryDisablePermission
	default:
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_operation_invalid")
	}
	workspaceContext, claims, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) || !organizationUnitParentScopeAllows(principal, permissionKey, request.OrganizationID) {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_scope_denied")
	}
	fingerprint, err := identityOrganizationUnitMutationRequestFingerprint(request, principal.UserID, claims.Audience)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryResult{}, err
	}
	var result identitymodel.IdentityOrganizationUnitDeliveryResult
	err = s.dependencies.Transactions.WithinIdentityTransaction(workspaceContext, func(transactionContext context.Context) error {
		if receipt, found, loadErr := s.dependencies.Repository.GetIdentityOrganizationUnitDeliveryReceipt(transactionContext, principal.WorkspaceID, request.IdempotencyKey); loadErr != nil {
			return loadErr
		} else if found {
			if receipt.RequestFingerprint != fingerprint || receipt.Result.Organization.OrganizationUnitID != request.OrganizationID || receipt.Result.Organization.NodeType != request.NodeType {
				return organizationUnitDeliveryError(apperror.KindConflict, "backend.idempotency_key_reused")
			}
			result = receipt.Result
			result.Replayed = true
			return nil
		}

		current, found, loadErr := s.dependencies.Identity.FindOrganizationUnit(transactionContext, request.OrganizationID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return organizationUnitDeliveryError(apperror.KindNotFound, "backend.identity.organization_unit_not_found")
		}
		if current.NodeType != request.NodeType {
			return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_type_conflict")
		}
		if current.Status == identitymodel.IdentityStatusDisabled && request.Operation == identitymodel.IdentityOrganizationUnitDisable {
			return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_already_disabled")
		}
		currentFingerprint := identityOrganizationUnitDeliveryFingerprint(current)
		state, stateFound, stateErr := s.dependencies.Repository.GetIdentityOrganizationUnitDeliveryState(transactionContext, principal.WorkspaceID, current.OrganizationUnitID)
		if stateErr != nil {
			return stateErr
		}
		currentVersion := int64(1)
		if stateFound {
			currentVersion = state.Version
			if state.StateFingerprint != currentFingerprint {
				return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
			}
		}
		if request.ExpectedVersion != currentVersion {
			return organizationUnitDeliveryError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		desired := current
		if request.Operation == identitymodel.IdentityOrganizationUnitRename {
			desired.Name = request.Name
		} else {
			desired.Status = identitymodel.IdentityStatusDisabled
		}
		prepared, related, prepareErr := s.dependencies.Identity.PrepareOrganizationUnitForAtomicDelivery(transactionContext, desired)
		if prepareErr != nil {
			return prepareErr
		}
		mutation := identitymodel.IdentityOrganizationUnitDeliveryMutation{
			WorkspaceID: principal.WorkspaceID, ActorID: principal.UserID, IdempotencyKey: request.IdempotencyKey,
			RequestFingerprint: fingerprint, Operation: request.Operation, Organization: prepared, RelatedOrganizations: related,
			ExpectedVersion: request.ExpectedVersion, CurrentFingerprint: currentFingerprint,
			DataScope: identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
		}
		receipt, executeErr := s.dependencies.Repository.ExecuteIdentityOrganizationUnitDelivery(transactionContext, mutation)
		if executeErr != nil {
			return fmt.Errorf("persist Identity organization unit mutation: %w", executeErr)
		}
		if appendErr := s.dependencies.Audit.AppendAudit(transactionContext, auditapplication.AuditAppendRequest{
			IdempotencyKey: "identity-organization-unit-delivery:" + request.IdempotencyKey,
			Family:         auditcontract.EventFamilyIdentityGovernance, Event: "identity.organization_unit_delivery." + string(request.Operation),
			ObjectKey: identitycontract.IdentityOrganizationUnitObjectKey, RecordID: request.OrganizationID, Principal: principal,
			Summary: "Runtime handler mutated an Identity organization unit", After: organizationUnitDeliveryAuditMap(receipt.Result.Organization),
			Metadata: map[string]any{"application_key": claims.Audience, "idempotency_key": request.IdempotencyKey},
		}); appendErr != nil {
			return fmt.Errorf("append Identity organization unit audit: %w", appendErr)
		}
		result = receipt.Result
		return nil
	})
	return result, err
}

func (s *IdentityOrganizationUnitDeliveryApplicationService) List(ctx context.Context, request IdentityOrganizationUnitListRequest) (identitymodel.IdentityDeliveredOrganizationUnitPage, error) {
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	request.Cursor = strings.TrimSpace(request.Cursor)
	if request.ContractVersion != IdentityOrganizationUnitDeliveryContractVersionV1 || request.AccessToken == "" || !validDeliveredOrganizationUnitType(request.NodeType) {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_projection_invalid")
	}
	pageSize, err := normalizeOrganizationUnitPageSize(request.PageSize)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, err
	}
	afterID, err := decodeOrganizationUnitCursor(request.Cursor)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, err
	}
	workspaceContext, _, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, err
	}
	permissionKey := identitycontract.IdentityOrganizationUnitDeliveryListPermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, organizationUnitDeliveryError(apperror.KindForbidden, "backend.identity.organization_unit_projection_denied")
	}
	items, err := s.dependencies.Repository.ListIdentityOrganizationUnitsPage(workspaceContext, principal.WorkspaceID, request.NodeType, identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey), afterID, pageSize+1)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnitPage{}, err
	}
	page := identitymodel.IdentityDeliveredOrganizationUnitPage{Items: items}
	if len(items) > pageSize {
		page.Items = append([]identitymodel.IdentityDeliveredOrganizationUnit(nil), items[:pageSize]...)
		page.NextCursor, err = encodeOrganizationUnitCursor(page.Items[len(page.Items)-1].ID)
		if err != nil {
			return identitymodel.IdentityDeliveredOrganizationUnitPage{}, err
		}
	}
	return page, nil
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
	if receipted.OrganizationUnitID != request.OrganizationID || receipted.Code != request.Code || receipted.Name != request.Name || receipted.NodeType != request.NodeType ||
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
	return nodeType.Valid() && nodeType != identitymodel.IdentityOrganizationUnitCompany
}

func validOrganizationUnitDeliveryParent(parent identitymodel.IdentityOrganizationUnit, found bool) bool {
	return found && strings.TrimSpace(parent.OrganizationUnitID) != "" && parent.NodeType.Valid() && parent.Status == identitymodel.IdentityStatusActive
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

func identityOrganizationUnitMutationRequestFingerprint(request IdentityOrganizationUnitMutationRequest, actorID, audience string) (string, error) {
	request.AccessToken = ""
	payload, err := json.Marshal(struct {
		Request  IdentityOrganizationUnitMutationRequest `json:"request"`
		ActorID  string                                  `json:"actor_id"`
		Audience string                                  `json:"audience"`
	}{Request: request, ActorID: actorID, Audience: audience})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

type identityOrganizationUnitCursor struct {
	Version int   `json:"v"`
	AfterID int64 `json:"after_id"`
}

func normalizeOrganizationUnitPageSize(pageSize int) (int, error) {
	if pageSize == 0 {
		return IdentityOrganizationUnitDefaultPageSize, nil
	}
	if pageSize < 1 || pageSize > IdentityOrganizationUnitMaxPageSize {
		return 0, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_page_size_invalid")
	}
	return pageSize, nil
}

func encodeOrganizationUnitCursor(afterID int64) (string, error) {
	payload, err := json.Marshal(identityOrganizationUnitCursor{Version: 1, AfterID: afterID})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeOrganizationUnitCursor(cursor string) (int64, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	if len(cursor) > 2048 {
		return 0, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_cursor_invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_cursor_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded identityOrganizationUnitCursor
	if err := decoder.Decode(&decoded); err != nil {
		return 0, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_cursor_invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || decoded.Version != 1 || decoded.AfterID < 1 {
		return 0, organizationUnitDeliveryError(apperror.KindBadRequest, "backend.identity.organization_unit_cursor_invalid")
	}
	return decoded.AfterID, nil
}

func identityOrganizationUnitDeliveryFingerprint(organization identitymodel.IdentityOrganizationUnit) string {
	organization.ID = 0
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func identityDeliveredOrganizationUnitFingerprint(organization identitymodel.IdentityDeliveredOrganizationUnit) string {
	parentID := organization.ParentOrganizationID
	return identityOrganizationUnitDeliveryFingerprint(identitymodel.IdentityOrganizationUnit{
		ID: organization.ID, OrganizationUnitID: organization.OrganizationUnitID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
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
		ID: organization.ID, OrganizationUnitID: organization.OrganizationUnitID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		Status: string(organization.Status), ParentOrganizationID: identityOrganizationUnitParentID(organization.ParentID),
		Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...), Depth: organization.Depth,
		SortOrder: organization.SortOrder, Version: version,
	}
}

func organizationUnitDeliveryAuditMap(organization identitymodel.IdentityDeliveredOrganizationUnit) map[string]any {
	return map[string]any{
		"id": organization.ID, "organization_unit_id": organization.OrganizationUnitID, "code": organization.Code, "name": organization.Name, "node_type": organization.NodeType,
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
