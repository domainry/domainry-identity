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

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

const IdentityStoreOrganizationDeliveryContractVersionV1 = "domainry-identity-store-organization-delivery-v1"

const (
	IdentityStoreOrganizationDefaultPageSize = 50
	IdentityStoreOrganizationMaxPageSize     = 100
)

type IdentityStoreOrganizationDeliveryRequest struct {
	ContractVersion      string
	AccessToken          string
	IdempotencyKey       string
	Operation            identitymodel.IdentityStoreOrganizationOperation
	OrganizationID       string
	Code                 string
	Name                 string
	ParentOrganizationID string
	SortOrder            int
	ExpectedVersion      int64
}

type IdentityStoreOrganizationResolveRequest struct {
	ContractVersion string
	AccessToken     string
	OrganizationID  string
}

type IdentityStoreOrganizationListRequest struct {
	ContractVersion string
	AccessToken     string
	PageSize        int
	Cursor          string
}

type IdentityStoreOrganizationDeliveryDependencies struct {
	WorkspaceID    string
	Authentication IdentityHandlerDeliveryAuthenticator
	Applications   IdentityHandlerDeliveryApplicationRegistry
	Identity       *IdentityApplicationService
	Transactions   identityrepository.IdentityTransactionManager
	Repository     identityrepository.IdentityStoreOrganizationDeliveryRepository
	Audit          auditapplication.AuditAppender
}

type IdentityStoreOrganizationDeliveryApplicationService struct {
	dependencies IdentityStoreOrganizationDeliveryDependencies
}

func NewIdentityStoreOrganizationDeliveryApplicationService(dependencies IdentityStoreOrganizationDeliveryDependencies) *IdentityStoreOrganizationDeliveryApplicationService {
	return &IdentityStoreOrganizationDeliveryApplicationService{dependencies: dependencies}
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) Deliver(ctx context.Context, request IdentityStoreOrganizationDeliveryRequest) (identitymodel.IdentityStoreOrganizationDeliveryResult, error) {
	if s == nil || s.dependencies.Identity == nil || s.dependencies.Transactions == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, storeOrganizationError(apperror.KindInternal, "backend.identity.store_organization_delivery_unavailable")
	}
	request.ContractVersion, request.AccessToken, request.IdempotencyKey = strings.TrimSpace(request.ContractVersion), strings.TrimSpace(request.AccessToken), strings.TrimSpace(request.IdempotencyKey)
	request.OrganizationID, request.Code, request.Name = strings.TrimSpace(request.OrganizationID), strings.TrimSpace(request.Code), strings.TrimSpace(request.Name)
	request.ParentOrganizationID = strings.TrimSpace(request.ParentOrganizationID)
	if request.ContractVersion != IdentityStoreOrganizationDeliveryContractVersionV1 || request.AccessToken == "" || request.IdempotencyKey == "" || request.OrganizationID == "" || request.ExpectedVersion < 0 || request.SortOrder < 0 {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_delivery_invalid")
	}
	if err := validateStoreOrganizationDeliveryRequest(request); err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, err
	}
	workspaceContext, claims, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, err
	}
	permissionKey := storeOrganizationPermissionForOperation(request.Operation)
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
	}
	fingerprint, err := identityStoreOrganizationRequestFingerprint(request, principal.UserID, claims.Audience)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryResult{}, err
	}
	var result identitymodel.IdentityStoreOrganizationDeliveryResult
	err = s.dependencies.Transactions.WithinIdentityTransaction(workspaceContext, func(transactionContext context.Context) error {
		if receipt, found, loadErr := s.dependencies.Repository.GetIdentityStoreOrganizationDeliveryReceipt(transactionContext, principal.WorkspaceID, request.IdempotencyKey); loadErr != nil {
			return loadErr
		} else if found {
			if receipt.RequestFingerprint != fingerprint {
				return storeOrganizationError(apperror.KindConflict, "backend.idempotency_key_reused")
			}
			if replayErr := s.authorizeReplay(transactionContext, request, receipt, principal, permissionKey); replayErr != nil {
				return replayErr
			}
			result = receipt.Result
			result.Replayed = true
			return nil
		}

		mutation, before, prepareErr := s.prepareMutation(transactionContext, request, principal, permissionKey, fingerprint)
		if prepareErr != nil {
			return fmt.Errorf("prepare Identity store organization delivery: %w", prepareErr)
		}
		receipt, executeErr := s.dependencies.Repository.ExecuteIdentityStoreOrganizationDelivery(transactionContext, mutation)
		if executeErr != nil {
			return fmt.Errorf("persist Identity store organization delivery: %w", executeErr)
		}
		if err := s.dependencies.Audit.AppendAudit(transactionContext, auditapplication.AuditAppendRequest{
			IdempotencyKey: "identity-store-organization-delivery:" + request.IdempotencyKey,
			Event:          "identity.store_organization_delivery." + string(request.Operation),
			ObjectKey:      identitycontract.IdentityOrganizationUnitObjectKey,
			RecordID:       request.OrganizationID,
			Principal:      principal,
			Summary:        "Runtime handler delivered an Identity store organization",
			Before:         storeOrganizationAuditMap(before),
			After:          storeOrganizationProjectionAuditMap(receipt.Result.Organization),
			Metadata: map[string]any{
				"application_key": claims.Audience, "idempotency_key": request.IdempotencyKey,
			},
		}); err != nil {
			return fmt.Errorf("append Identity store organization delivery audit: %w", err)
		}
		result = receipt.Result
		return nil
	})
	return result, err
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) authorizeReplay(ctx context.Context, request IdentityStoreOrganizationDeliveryRequest, receipt identitymodel.IdentityStoreOrganizationDeliveryReceipt, principal identitymodel.Principal, permissionKey string) error {
	receipted := receipt.Result.Organization
	if strings.TrimSpace(receipted.ID) == "" || receipted.ID != request.OrganizationID {
		return storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_external_change")
	}
	if request.Operation != identitymodel.IdentityStoreOrganizationCreate {
		if !storeOrganizationScopeAllows(principal, permissionKey, receipted.ID) {
			return storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
		}
		return nil
	}

	// Create is authorized against its persisted company parent, not the child
	// store ID. Re-read every fact required for that decision so a durable
	// receipt cannot become an authorization oracle after external mutations.
	current, found, err := s.dependencies.Identity.FindOrganizationUnit(ctx, receipted.ID)
	if err != nil {
		return err
	}
	receiptedParentID := strings.TrimSpace(receipted.ParentOrganizationID)
	if !found || current.NodeType != identitymodel.IdentityOrganizationUnitStore ||
		(current.Status != identitymodel.IdentityStatusActive && current.Status != identitymodel.IdentityStatusDisabled) ||
		receipted.Code != request.Code || receipted.Name != request.Name || receipted.Status != string(identitymodel.IdentityStatusActive) ||
		receipted.SortOrder != request.SortOrder || receipted.Version != 1 || receiptedParentID == "" ||
		receiptedParentID != request.ParentOrganizationID || storeOrganizationParentID(current.ParentID) != receiptedParentID {
		return storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_external_change")
	}
	state, stateFound, err := s.dependencies.Repository.GetIdentityStoreOrganizationState(ctx, principal.WorkspaceID, current.ID)
	if err != nil {
		return err
	}
	if !stateFound || state.Version < receipted.Version || state.StateFingerprint != identityStoreOrganizationFingerprint(current) {
		return storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_external_change")
	}
	parent, parentFound, err := s.dependencies.Identity.FindOrganizationUnit(ctx, receiptedParentID)
	if err != nil {
		return err
	}
	if !parentFound || parent.NodeType != identitymodel.IdentityOrganizationUnitCompany || parent.Status != identitymodel.IdentityStatusActive {
		return storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_external_change")
	}
	if !storeOrganizationScopeAllows(principal, permissionKey, receiptedParentID) {
		return storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
	}
	return nil
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) Resolve(ctx context.Context, request IdentityStoreOrganizationResolveRequest) (identitymodel.IdentityStoreOrganization, error) {
	request.ContractVersion, request.AccessToken, request.OrganizationID = strings.TrimSpace(request.ContractVersion), strings.TrimSpace(request.AccessToken), strings.TrimSpace(request.OrganizationID)
	if request.ContractVersion != IdentityStoreOrganizationDeliveryContractVersionV1 || request.AccessToken == "" || request.OrganizationID == "" {
		return identitymodel.IdentityStoreOrganization{}, storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_projection_invalid")
	}
	workspaceContext, _, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityStoreOrganization{}, err
	}
	permissionKey := identitycontract.IdentityStoreOrganizationDeliveryResolvePermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityStoreOrganization{}, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_projection_denied")
	}
	organization, found, err := s.dependencies.Identity.OrganizationUnitByIDWithinDataScope(workspaceContext, request.OrganizationID, principal, permissionKey)
	if err != nil {
		return identitymodel.IdentityStoreOrganization{}, err
	}
	if !found || organization.NodeType != identitymodel.IdentityOrganizationUnitStore {
		return identitymodel.IdentityStoreOrganization{}, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_projection_denied")
	}
	if err := s.validatePersistedStoreParent(workspaceContext, organization); err != nil {
		return identitymodel.IdentityStoreOrganization{}, err
	}
	return s.project(workspaceContext, organization)
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) List(ctx context.Context, request IdentityStoreOrganizationListRequest) (identitymodel.IdentityStoreOrganizationPage, error) {
	request.ContractVersion, request.AccessToken, request.Cursor = strings.TrimSpace(request.ContractVersion), strings.TrimSpace(request.AccessToken), strings.TrimSpace(request.Cursor)
	if request.ContractVersion != IdentityStoreOrganizationDeliveryContractVersionV1 || request.AccessToken == "" {
		return identitymodel.IdentityStoreOrganizationPage{}, storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_projection_invalid")
	}
	pageSize, err := normalizeStoreOrganizationPageSize(request.PageSize)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationPage{}, err
	}
	afterID, err := decodeStoreOrganizationCursor(request.Cursor)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationPage{}, err
	}
	workspaceContext, _, principal, err := s.authorize(ctx, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationPage{}, err
	}
	permissionKey := identitycontract.IdentityStoreOrganizationDeliveryListPermission
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey) {
		return identitymodel.IdentityStoreOrganizationPage{}, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_projection_denied")
	}
	items, err := s.dependencies.Repository.ListIdentityStoreOrganizationsPage(
		workspaceContext,
		principal.WorkspaceID,
		identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
		afterID,
		pageSize+1,
	)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationPage{}, err
	}
	page := identitymodel.IdentityStoreOrganizationPage{Items: items}
	if len(items) > pageSize {
		page.Items = append([]identitymodel.IdentityStoreOrganization(nil), items[:pageSize]...)
		page.NextCursor, err = encodeStoreOrganizationCursor(page.Items[len(page.Items)-1].ID)
		if err != nil {
			return identitymodel.IdentityStoreOrganizationPage{}, err
		}
	}
	return page, nil
}

type identityStoreOrganizationCursor struct {
	Version int    `json:"v"`
	AfterID string `json:"after_id"`
}

func normalizeStoreOrganizationPageSize(pageSize int) (int, error) {
	if pageSize == 0 {
		return IdentityStoreOrganizationDefaultPageSize, nil
	}
	if pageSize < 1 || pageSize > IdentityStoreOrganizationMaxPageSize {
		return 0, storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_page_size_invalid")
	}
	return pageSize, nil
}

func encodeStoreOrganizationCursor(afterID string) (string, error) {
	payload, err := json.Marshal(identityStoreOrganizationCursor{Version: 1, AfterID: strings.TrimSpace(afterID)})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeStoreOrganizationCursor(cursor string) (string, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return "", nil
	}
	if len(cursor) > 2048 {
		return "", storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_cursor_invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_cursor_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded identityStoreOrganizationCursor
	if err := decoder.Decode(&decoded); err != nil {
		return "", storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_cursor_invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || decoded.Version != 1 || strings.TrimSpace(decoded.AfterID) == "" || decoded.AfterID != strings.TrimSpace(decoded.AfterID) || len(decoded.AfterID) > 255 {
		return "", storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_cursor_invalid")
	}
	return decoded.AfterID, nil
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) authorize(ctx context.Context, accessToken string) (context.Context, authmodel.AuthClaims, identitymodel.Principal, error) {
	if err := ctx.Err(); err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	if s == nil || s.dependencies.Authentication == nil || s.dependencies.Applications == nil || s.dependencies.Identity == nil || s.dependencies.Repository == nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, storeOrganizationError(apperror.KindInternal, "backend.identity.store_organization_delivery_unavailable")
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
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, storeOrganizationError(apperror.KindForbidden, "identity.store_organization_delivery_application_scope_mismatch")
	}
	workspaceContext := requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal, err := s.dependencies.Authentication.PrincipalFromBearer(workspaceContext, "Bearer "+accessToken, requestcontext.RequestID(ctx))
	if err != nil {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, err
	}
	if !principal.Known || principal.UserID != claims.Subject || principal.WorkspaceID != workspaceID {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_actor_invalid")
	}
	if principal.AuthorizationRevision == "" || principal.AuthorizationRevision != claims.AuthorizationRevision {
		return ctx, authmodel.AuthClaims{}, identitymodel.Principal{}, storeOrganizationError(apperror.KindConflict, "auth.authorization_stale")
	}
	return workspaceContext, claims, principal, nil
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) prepareMutation(ctx context.Context, request IdentityStoreOrganizationDeliveryRequest, principal identitymodel.Principal, permissionKey, requestFingerprint string) (identitymodel.IdentityStoreOrganizationDeliveryMutation, identitymodel.IdentityOrganizationUnit, error) {
	current, found, err := s.dependencies.Identity.FindOrganizationUnit(ctx, request.OrganizationID)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, err
	}
	var desired identitymodel.IdentityOrganizationUnit
	parentID := request.ParentOrganizationID
	switch request.Operation {
	case identitymodel.IdentityStoreOrganizationCreate:
		if found || request.ExpectedVersion != 0 {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
		if !storeOrganizationScopeAllows(principal, permissionKey, parentID) {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
		}
		desired = identitymodel.IdentityOrganizationUnit{
			ID: request.OrganizationID, Code: request.Code, Name: request.Name, NodeType: identitymodel.IdentityOrganizationUnitStore,
			ParentID: &parentID, SortOrder: request.SortOrder, Status: identitymodel.IdentityStatusActive,
		}
	case identitymodel.IdentityStoreOrganizationRename:
		if !found {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindNotFound, "backend.identity.store_organization_not_found")
		}
		if !storeOrganizationScopeAllows(principal, permissionKey, current.ID) {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
		}
		desired = current
		desired.Name = request.Name
		parentID = storeOrganizationParentID(current.ParentID)
	case identitymodel.IdentityStoreOrganizationDisable:
		if !found {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindNotFound, "backend.identity.store_organization_not_found")
		}
		if !storeOrganizationScopeAllows(principal, permissionKey, current.ID) {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
		}
		if current.Status == identitymodel.IdentityStatusDisabled {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_already_disabled")
		}
		desired = current
		desired.Status = identitymodel.IdentityStatusDisabled
		parentID = storeOrganizationParentID(current.ParentID)
	}
	if found && current.NodeType != identitymodel.IdentityOrganizationUnitStore {
		return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_type_conflict")
	}
	parent, parentFound, err := s.dependencies.Identity.FindOrganizationUnit(ctx, parentID)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, err
	}
	if !parentFound || parent.NodeType != identitymodel.IdentityOrganizationUnitCompany || (request.Operation == identitymodel.IdentityStoreOrganizationCreate && parent.Status != identitymodel.IdentityStatusActive) {
		return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_parent_invalid")
	}

	prepared, related, err := s.dependencies.Identity.PrepareOrganizationUnitForAtomicDelivery(ctx, desired)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, err
	}
	mutation := identitymodel.IdentityStoreOrganizationDeliveryMutation{
		WorkspaceID: principal.WorkspaceID, ActorID: principal.UserID, IdempotencyKey: request.IdempotencyKey,
		RequestFingerprint: requestFingerprint, Operation: request.Operation, Organization: prepared,
		RelatedOrganizations: related, ExpectedVersion: request.ExpectedVersion,
		DataScope: identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey),
	}
	if found {
		mutation.CurrentFingerprint = identityStoreOrganizationFingerprint(current)
		state, stateFound, err := s.dependencies.Repository.GetIdentityStoreOrganizationState(ctx, principal.WorkspaceID, current.ID)
		if err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, err
		}
		currentVersion := int64(1)
		if stateFound {
			currentVersion = state.Version
			if state.StateFingerprint != mutation.CurrentFingerprint {
				return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_external_change")
			}
		}
		if request.ExpectedVersion != currentVersion {
			return identitymodel.IdentityStoreOrganizationDeliveryMutation{}, current, storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
	}
	return mutation, current, nil
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) validatePersistedStoreParent(ctx context.Context, organization identitymodel.IdentityOrganizationUnit) error {
	parentID := storeOrganizationParentID(organization.ParentID)
	parent, found, err := s.dependencies.Identity.FindOrganizationUnit(ctx, parentID)
	if err != nil {
		return err
	}
	if !found || parent.NodeType != identitymodel.IdentityOrganizationUnitCompany {
		return storeOrganizationError(apperror.KindConflict, "backend.identity.store_organization_parent_invalid")
	}
	return nil
}

func (s *IdentityStoreOrganizationDeliveryApplicationService) project(ctx context.Context, organization identitymodel.IdentityOrganizationUnit) (identitymodel.IdentityStoreOrganization, error) {
	state, found, err := s.dependencies.Repository.GetIdentityStoreOrganizationState(ctx, s.dependencies.WorkspaceID, organization.ID)
	if err != nil {
		return identitymodel.IdentityStoreOrganization{}, err
	}
	version := int64(1)
	if found {
		version = state.Version
	}
	return identityStoreOrganizationProjection(organization, version), nil
}

func validateStoreOrganizationDeliveryRequest(request IdentityStoreOrganizationDeliveryRequest) error {
	switch request.Operation {
	case identitymodel.IdentityStoreOrganizationCreate:
		if request.ExpectedVersion != 0 || request.Code == "" || request.Name == "" || request.ParentOrganizationID == "" {
			return storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_delivery_invalid")
		}
	case identitymodel.IdentityStoreOrganizationRename:
		if request.ExpectedVersion < 1 || request.Name == "" || request.Code != "" || request.ParentOrganizationID != "" || request.SortOrder != 0 {
			return storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_delivery_invalid")
		}
	case identitymodel.IdentityStoreOrganizationDisable:
		if request.ExpectedVersion < 1 || request.Name != "" || request.Code != "" || request.ParentOrganizationID != "" || request.SortOrder != 0 {
			return storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_delivery_invalid")
		}
	default:
		return storeOrganizationError(apperror.KindBadRequest, "backend.identity.store_organization_operation_invalid")
	}
	return nil
}

func storeOrganizationPermissionForOperation(operation identitymodel.IdentityStoreOrganizationOperation) string {
	switch operation {
	case identitymodel.IdentityStoreOrganizationCreate:
		return identitycontract.IdentityStoreOrganizationDeliveryCreatePermission
	case identitymodel.IdentityStoreOrganizationRename:
		return identitycontract.IdentityStoreOrganizationDeliveryRenamePermission
	case identitymodel.IdentityStoreOrganizationDisable:
		return identitycontract.IdentityStoreOrganizationDeliveryDisablePermission
	default:
		return ""
	}
}

func storeOrganizationScopeAllows(principal identitymodel.Principal, permissionKey, organizationID string) bool {
	return identitycontract.IdentityPermissionDataScopeAllows(principal, permissionKey, identitycontract.IdentityResourceFacts{RecordID: organizationID, OwnerOrgID: organizationID})
}

func identityStoreOrganizationRequestFingerprint(request IdentityStoreOrganizationDeliveryRequest, actorID, audience string) (string, error) {
	request.AccessToken = ""
	payload, err := json.Marshal(struct {
		Request  IdentityStoreOrganizationDeliveryRequest `json:"request"`
		ActorID  string                                   `json:"actor_id"`
		Audience string                                   `json:"audience"`
	}{Request: request, ActorID: actorID, Audience: audience})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func identityStoreOrganizationFingerprint(organization identitymodel.IdentityOrganizationUnit) string {
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func identityStoreOrganizationProjection(organization identitymodel.IdentityOrganizationUnit, version int64) identitymodel.IdentityStoreOrganization {
	return identitymodel.IdentityStoreOrganization{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, Status: string(organization.Status),
		ParentOrganizationID: storeOrganizationParentID(organization.ParentID), Path: organization.Path,
		AncestorIDs: append([]string(nil), organization.AncestorIDs...), Depth: organization.Depth, SortOrder: organization.SortOrder, Version: version,
	}
}

func storeOrganizationAuditMap(organization identitymodel.IdentityOrganizationUnit) map[string]any {
	if strings.TrimSpace(organization.ID) == "" {
		return nil
	}
	return map[string]any{"id": organization.ID, "name": organization.Name, "status": organization.Status, "parent_id": storeOrganizationParentID(organization.ParentID)}
}

func storeOrganizationParentID(parentID *string) string {
	if parentID == nil {
		return ""
	}
	return strings.TrimSpace(*parentID)
}

func storeOrganizationProjectionAuditMap(organization identitymodel.IdentityStoreOrganization) map[string]any {
	return map[string]any{"id": organization.ID, "name": organization.Name, "status": organization.Status, "parent_id": organization.ParentOrganizationID, "version": organization.Version}
}

func storeOrganizationError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

// ForWorkspace returns an immutable host-authorized view; callers supply the
// matching source-owned application registry after token verification.
func (s *IdentityStoreOrganizationDeliveryApplicationService) ForWorkspace(workspaceID string, applications IdentityHandlerDeliveryApplicationRegistry) *IdentityStoreOrganizationDeliveryApplicationService {
	clone := *s
	clone.dependencies.WorkspaceID = workspaceID
	clone.dependencies.Applications = applications
	return &clone
}
