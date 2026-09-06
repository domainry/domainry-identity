package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

const (
	IdentityWorkspaceUsageContractVersionV1 = "domainry-identity-workspace-usage-v1"
	IdentityWorkspaceUsageContractVersionV2 = "domainry-identity-workspace-usage-v2"
	IdentityWorkspaceUsageContractVersionV3 = "domainry-identity-workspace-usage-v3"
	IdentityWorkspaceUsageContractHashV2    = "1e58b9b154cd80fbd364dbbd2e1bad9ca1b9420ce25c321f1cca0878c17a3c14"
	IdentityWorkspaceUsageContractHashV3    = "5f6f8a71e4a9c569628a08a1d46e41bf212e0ec4b0ba64f5a3a815bb857d5f7e"
)

const (
	IdentityWorkspaceUsageAggregatePermission = identitycontract.IdentityWorkspaceIdentityUsageAggregate
	IdentityWorkspaceUsageDefaultPageSize     = 50
	IdentityWorkspaceUsageMaxPageSize         = 100
)

const identityWorkspaceUsageSystemPurpose = "aggregate authorized Workspace identity usage"

type IdentityWorkspaceUsageRequest struct {
	ContractVersion string
	ContractHash    string
	Authorization   identitymodel.IdentityWorkspaceUsageGrant
	AccessToken     string
	PageSize        int
	Cursor          string
}

type IdentityWorkspaceUsageResolveRequest struct {
	ContractVersion string
	ContractHash    string
	Authorization   identitymodel.IdentityWorkspaceUsageGrant
	AccessToken     string
	WorkspaceCode   string
}

type IdentityWorkspaceUsageAuthority interface {
	AuthorizeWorkspaceIdentityUsage(context.Context, string, string) (identitymodel.IdentityWorkspaceUsageGrant, error)
	ListAuthorizedWorkspaceIdentityUsage(context.Context, identitymodel.IdentityWorkspaceUsageGrant, string, int, string) (identitymodel.IdentityWorkspaceUsageCatalogPage, error)
	ResolveAuthorizedWorkspaceIdentityUsage(context.Context, identitymodel.IdentityWorkspaceUsageGrant, string) (identitymodel.IdentityWorkspaceUsageCatalogEntry, error)
}

type IdentityWorkspaceUsageDependencies struct {
	ApplicationKey string
	Authority      IdentityWorkspaceUsageAuthority
	Repository     identityrepository.IdentityWorkspaceUsageRepository
	Audit          auditapplication.AuditAppender
	// CursorKey is the host-owned stable AES-256 key used only for opaque usage
	// cursors. Persisting the same key preserves pagination across restarts;
	// changing or losing it invalidates outstanding cursors fail closed.
	CursorKey []byte
}

type IdentityWorkspaceUsageApplicationService struct {
	dependencies IdentityWorkspaceUsageDependencies
}

func NewIdentityWorkspaceUsageApplicationService(dependencies IdentityWorkspaceUsageDependencies) *IdentityWorkspaceUsageApplicationService {
	dependencies.CursorKey = append([]byte(nil), dependencies.CursorKey...)
	return &IdentityWorkspaceUsageApplicationService{dependencies: dependencies}
}

func (s *IdentityWorkspaceUsageApplicationService) Authorize(ctx context.Context, accessToken string) (identitymodel.IdentityWorkspaceUsageGrant, error) {
	if s == nil || s.dependencies.Authority == nil || strings.TrimSpace(s.dependencies.ApplicationKey) == "" {
		return identitymodel.IdentityWorkspaceUsageGrant{}, identityWorkspaceUsageError(apperror.KindInternal, "backend.identity.workspace_usage_unavailable")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return identitymodel.IdentityWorkspaceUsageGrant{}, identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_request_invalid")
	}
	grant, err := s.dependencies.Authority.AuthorizeWorkspaceIdentityUsage(ctx, accessToken, IdentityWorkspaceUsageAggregatePermission)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsageGrant{}, fmt.Errorf("authorize Identity Workspace usage: %w", err)
	}
	grant = normalizeIdentityWorkspaceUsageGrant(grant)
	if !validIdentityWorkspaceUsageGrant(grant, s.dependencies.ApplicationKey) {
		return identitymodel.IdentityWorkspaceUsageGrant{}, identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_authority_invalid")
	}
	return grant, nil
}

func (s *IdentityWorkspaceUsageApplicationService) List(ctx context.Context, request IdentityWorkspaceUsageRequest) (identitymodel.IdentityWorkspaceUsagePage, error) {
	if s == nil || s.dependencies.Authority == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil || strings.TrimSpace(s.dependencies.ApplicationKey) == "" || len(s.dependencies.CursorKey) != 32 {
		return identitymodel.IdentityWorkspaceUsagePage{}, identityWorkspaceUsageError(apperror.KindInternal, "backend.identity.workspace_usage_unavailable")
	}
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.ContractHash = strings.TrimSpace(request.ContractHash)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	request.Cursor = strings.TrimSpace(request.Cursor)
	if !validIdentityWorkspaceUsageListContract(request.ContractVersion, request.ContractHash) || request.AccessToken == "" && !validIdentityWorkspaceUsageGrant(normalizeIdentityWorkspaceUsageGrant(request.Authorization), s.dependencies.ApplicationKey) {
		return identitymodel.IdentityWorkspaceUsagePage{}, identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_request_invalid")
	}
	pageSize, err := normalizeIdentityWorkspaceUsagePageSize(request.PageSize)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, err
	}
	grant, err := s.authorization(ctx, request.Authorization, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, err
	}
	afterWorkspaceID, expectedCatalogRevision, err := decodeIdentityWorkspaceUsageCursor(request.Cursor, s.dependencies.CursorKey, grant, request.ContractVersion, request.ContractHash, pageSize)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, err
	}
	catalog, err := s.dependencies.Authority.ListAuthorizedWorkspaceIdentityUsage(ctx, grant, afterWorkspaceID, pageSize+1, expectedCatalogRevision)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, fmt.Errorf("list authorized Workspace usage catalog: %w", err)
	}
	catalog.CatalogRevision = strings.TrimSpace(catalog.CatalogRevision)
	if err := validateIdentityWorkspaceUsageCatalog(catalog, afterWorkspaceID, pageSize+1, expectedCatalogRevision); err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, err
	}
	selected := catalog.Workspaces
	hasNext := len(selected) > pageSize
	if hasNext {
		selected = selected[:pageSize]
	}
	workspaceIDs := make([]string, len(selected))
	for index, workspace := range selected {
		workspaceIDs[index] = workspace.WorkspaceID
	}
	items, err := s.count(ctx, workspaceIDs)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, err
	}
	result := identitymodel.IdentityWorkspaceUsagePage{Items: items}
	if hasNext {
		result.NextCursor, err = encodeIdentityWorkspaceUsageCursor(items[len(items)-1].WorkspaceID, catalog.CatalogRevision, s.dependencies.CursorKey, grant, request.ContractVersion, request.ContractHash, pageSize)
		if err != nil {
			return identitymodel.IdentityWorkspaceUsagePage{}, err
		}
	}
	principal := identityWorkspaceUsageAuditPrincipal(grant)
	if err := s.dependencies.Audit.AppendAudit(ctx, auditapplication.AuditAppendRequest{
		Event:     "identity.workspace_identity_usage.aggregate",
		ObjectKey: "identity.workspace_identity_usage",
		RecordID:  grant.InstallationID,
		Principal: principal,
		Summary:   "Aggregated authorized Workspace identity account usage",
		Metadata: map[string]any{
			"application_key": grant.ApplicationKey, "catalog_revision": catalog.CatalogRevision,
			"authority_audit_id": grant.AuthorizationAuditID, "contract_version": request.ContractVersion, "contract_hash": request.ContractHash,
			"page_size": pageSize, "result_count": len(items), "has_next": hasNext,
		},
	}); err != nil {
		return identitymodel.IdentityWorkspaceUsagePage{}, fmt.Errorf("append Identity Workspace usage audit: %w", err)
	}
	return result, nil
}

func (s *IdentityWorkspaceUsageApplicationService) Resolve(ctx context.Context, request IdentityWorkspaceUsageResolveRequest) (identitymodel.IdentityWorkspaceUsage, error) {
	if s == nil || s.dependencies.Authority == nil || s.dependencies.Repository == nil || s.dependencies.Audit == nil || strings.TrimSpace(s.dependencies.ApplicationKey) == "" {
		return identitymodel.IdentityWorkspaceUsage{}, identityWorkspaceUsageError(apperror.KindInternal, "backend.identity.workspace_usage_unavailable")
	}
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.ContractHash = strings.TrimSpace(request.ContractHash)
	request.AccessToken = strings.TrimSpace(request.AccessToken)
	rawWorkspaceCode := request.WorkspaceCode
	request.WorkspaceCode = strings.TrimSpace(request.WorkspaceCode)
	if request.ContractVersion != IdentityWorkspaceUsageContractVersionV3 || request.ContractHash != IdentityWorkspaceUsageContractHashV3 ||
		request.AccessToken == "" && !validIdentityWorkspaceUsageGrant(normalizeIdentityWorkspaceUsageGrant(request.Authorization), s.dependencies.ApplicationKey) ||
		request.WorkspaceCode == "" || request.WorkspaceCode != rawWorkspaceCode || len(request.WorkspaceCode) > 191 {
		return identitymodel.IdentityWorkspaceUsage{}, identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_resolve_request_invalid")
	}
	grant, err := s.authorization(ctx, request.Authorization, request.AccessToken)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsage{}, err
	}
	workspace, err := s.dependencies.Authority.ResolveAuthorizedWorkspaceIdentityUsage(ctx, grant, request.WorkspaceCode)
	if err != nil {
		return identitymodel.IdentityWorkspaceUsage{}, fmt.Errorf("resolve authorized Workspace usage scope: %w", err)
	}
	if err := validateIdentityWorkspaceUsageExactCatalog(workspace); err != nil {
		return identitymodel.IdentityWorkspaceUsage{}, err
	}
	items, err := s.count(ctx, []string{workspace.WorkspaceID})
	if err != nil {
		return identitymodel.IdentityWorkspaceUsage{}, err
	}
	if len(items) != 1 || items[0].WorkspaceID != workspace.WorkspaceID {
		return identitymodel.IdentityWorkspaceUsage{}, identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
	}
	principal := identityWorkspaceUsageAuditPrincipal(grant)
	if err := s.dependencies.Audit.AppendAudit(ctx, auditapplication.AuditAppendRequest{
		Event:     "identity.workspace_identity_usage.resolve",
		ObjectKey: "identity.workspace_identity_usage",
		RecordID:  grant.InstallationID,
		Principal: principal,
		Summary:   "Resolved authorized Workspace identity account usage",
		Metadata: map[string]any{
			"application_key": grant.ApplicationKey, "authority_audit_id": grant.AuthorizationAuditID,
			"contract_version": request.ContractVersion, "contract_hash": request.ContractHash, "result_count": 1,
		},
	}); err != nil {
		return identitymodel.IdentityWorkspaceUsage{}, fmt.Errorf("append exact Identity Workspace usage audit: %w", err)
	}
	return items[0], nil
}

func (s *IdentityWorkspaceUsageApplicationService) authorization(ctx context.Context, authorization identitymodel.IdentityWorkspaceUsageGrant, accessToken string) (identitymodel.IdentityWorkspaceUsageGrant, error) {
	authorization = normalizeIdentityWorkspaceUsageGrant(authorization)
	if validIdentityWorkspaceUsageGrant(authorization, s.dependencies.ApplicationKey) {
		return authorization, nil
	}
	return s.Authorize(ctx, accessToken)
}

func validIdentityWorkspaceUsageListContract(version, hash string) bool {
	return version == IdentityWorkspaceUsageContractVersionV2 && hash == IdentityWorkspaceUsageContractHashV2 ||
		version == IdentityWorkspaceUsageContractVersionV3 && hash == IdentityWorkspaceUsageContractHashV3
}

func (s *IdentityWorkspaceUsageApplicationService) count(ctx context.Context, workspaceIDs []string) ([]identitymodel.IdentityWorkspaceUsage, error) {
	items := make([]identitymodel.IdentityWorkspaceUsage, len(workspaceIDs))
	itemIndex := make(map[string]int, len(workspaceIDs))
	for index, workspaceID := range workspaceIDs {
		items[index].WorkspaceID = workspaceID
		itemIndex[workspaceID] = index
	}
	groups, err := s.dependencies.Repository.CountIdentityWorkspaceUsage(ctx, workspaceIDs)
	if err != nil {
		return nil, fmt.Errorf("count Identity Workspace usage: %w", err)
	}
	if err := applyIdentityWorkspaceUsageGroups(items, itemIndex, groups); err != nil {
		return nil, err
	}
	activeHumanRoles, err := s.dependencies.Repository.CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(ctx, workspaceIDs)
	if err != nil {
		return nil, fmt.Errorf("count active human Identity Workspace role usage: %w", err)
	}
	if err := applyIdentityWorkspaceActiveHumanRoleCounts(items, itemIndex, activeHumanRoles); err != nil {
		return nil, err
	}
	return items, nil
}

func normalizeIdentityWorkspaceUsagePageSize(value int) (int, error) {
	if value == 0 {
		return IdentityWorkspaceUsageDefaultPageSize, nil
	}
	if value < 1 || value > IdentityWorkspaceUsageMaxPageSize {
		return 0, identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_page_size_invalid")
	}
	return value, nil
}

func normalizeIdentityWorkspaceUsageGrant(grant identitymodel.IdentityWorkspaceUsageGrant) identitymodel.IdentityWorkspaceUsageGrant {
	grant.InstallationID = strings.TrimSpace(grant.InstallationID)
	grant.ApplicationKey = strings.TrimSpace(grant.ApplicationKey)
	grant.SubjectID = strings.TrimSpace(grant.SubjectID)
	grant.AuditWorkspaceID = strings.TrimSpace(grant.AuditWorkspaceID)
	grant.PermissionKey = strings.TrimSpace(grant.PermissionKey)
	grant.AuthorizationRevision = strings.TrimSpace(grant.AuthorizationRevision)
	grant.AuthorizationAuditID = strings.TrimSpace(grant.AuthorizationAuditID)
	return grant
}

func validIdentityWorkspaceUsageGrant(grant identitymodel.IdentityWorkspaceUsageGrant, applicationKey string) bool {
	if grant.InstallationID == "" || grant.ApplicationKey == "" || grant.SubjectID == "" || grant.AuditWorkspaceID == "" || grant.AuthorizationRevision == "" || grant.AuthorizationAuditID == "" {
		return false
	}
	if grant.ApplicationKey != strings.TrimSpace(applicationKey) || grant.PermissionKey != IdentityWorkspaceUsageAggregatePermission {
		return false
	}
	_, err := identitymodel.NewWorkspaceID(grant.AuditWorkspaceID)
	return err == nil
}

func validateIdentityWorkspaceUsageCatalog(catalog identitymodel.IdentityWorkspaceUsageCatalogPage, afterWorkspaceID string, fetchLimit int, expectedRevision string) error {
	if catalog.CatalogRevision == "" || len(catalog.Workspaces) > fetchLimit || (expectedRevision != "" && catalog.CatalogRevision != expectedRevision) {
		return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_catalog_invalid")
	}
	previous := strings.TrimSpace(afterWorkspaceID)
	for _, workspace := range catalog.Workspaces {
		workspaceID := strings.TrimSpace(workspace.WorkspaceID)
		if !workspace.Known || !workspace.Authorized || workspace.Status != "active" || workspaceID == "" || workspaceID != workspace.WorkspaceID || workspaceID <= previous {
			return identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_catalog_scope_invalid")
		}
		if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
			return identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_catalog_scope_invalid")
		}
		previous = workspaceID
	}
	return nil
}

func validateIdentityWorkspaceUsageExactCatalog(workspace identitymodel.IdentityWorkspaceUsageCatalogEntry) error {
	workspaceID := strings.TrimSpace(workspace.WorkspaceID)
	if !workspace.Known || !workspace.Authorized || workspace.Status != "active" || workspaceID == "" || workspaceID != workspace.WorkspaceID {
		return identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_catalog_scope_invalid")
	}
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_catalog_scope_invalid")
	}
	return nil
}

func applyIdentityWorkspaceUsageGroups(items []identitymodel.IdentityWorkspaceUsage, itemIndex map[string]int, groups []identitymodel.IdentityWorkspaceUsageGroup) error {
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		workspaceID := strings.TrimSpace(group.WorkspaceID)
		index, allowed := itemIndex[workspaceID]
		if !allowed || workspaceID != group.WorkspaceID || group.Count < 1 {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
		}
		key := group.WorkspaceID + "\x00" + string(group.AccountType) + "\x00" + string(group.Status)
		if _, duplicate := seen[key]; duplicate {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
		}
		seen[key] = struct{}{}
		if group.AccountType != identitymodel.IdentityAccountHuman && group.AccountType != identitymodel.IdentityAccountService && group.AccountType != identitymodel.IdentityAccountAutomation {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_account_type_invalid")
		}
		switch group.Status {
		case identitymodel.IdentityStatusDeleted:
			continue
		case identitymodel.IdentityStatusActive, identitymodel.IdentityStatusDisabled:
		default:
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_account_status_invalid")
		}
		counts := &items[index].Accounts
		switch group.AccountType {
		case identitymodel.IdentityAccountHuman:
			if group.Status == identitymodel.IdentityStatusActive {
				counts.ActiveHumanAccounts += group.Count
			} else {
				counts.DisabledHumanAccounts += group.Count
			}
		case identitymodel.IdentityAccountService:
			counts.ServiceAccounts += group.Count
		case identitymodel.IdentityAccountAutomation:
			counts.AutomationAccounts += group.Count
		}
	}
	return nil
}

func applyIdentityWorkspaceActiveHumanRoleCounts(items []identitymodel.IdentityWorkspaceUsage, itemIndex map[string]int, counts []identitymodel.IdentityWorkspaceActiveHumanRoleCount) error {
	seen := make(map[string]struct{}, len(counts))
	for _, count := range counts {
		workspaceID := strings.TrimSpace(count.WorkspaceID)
		index, allowed := itemIndex[workspaceID]
		if !allowed || workspaceID != count.WorkspaceID || count.Count < 1 {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
		}
		if _, duplicate := seen[workspaceID]; duplicate {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
		}
		seen[workspaceID] = struct{}{}
		if count.Count > items[index].Accounts.ActiveHumanAccounts {
			return identityWorkspaceUsageError(apperror.KindConflict, "backend.identity.workspace_usage_aggregate_invalid")
		}
		items[index].Accounts.ActiveHumanAccountsWithActiveRole = count.Count
	}
	return nil
}

type identityWorkspaceUsageCursor struct {
	Version               int    `json:"v"`
	ContractVersion       string `json:"contract_version"`
	ContractHash          string `json:"contract_hash"`
	PageSize              int    `json:"page_size"`
	AfterWorkspaceID      string `json:"after_workspace_id"`
	InstallationID        string `json:"installation_id"`
	ApplicationKey        string `json:"application_key"`
	SubjectID             string `json:"subject_id"`
	PermissionKey         string `json:"permission_key"`
	AuthorizationRevision string `json:"authorization_revision"`
	CatalogRevision       string `json:"catalog_revision"`
}

const identityWorkspaceUsageCursorAdditionalData = "domainry.identity.workspace-usage.cursor.v2:" + IdentityWorkspaceUsageContractHashV2

func encodeIdentityWorkspaceUsageCursor(afterWorkspaceID, catalogRevision string, key []byte, grant identitymodel.IdentityWorkspaceUsageGrant, contractVersion, contractHash string, pageSize int) (string, error) {
	payload, err := json.Marshal(identityWorkspaceUsageCursor{
		Version: 2, ContractVersion: contractVersion, ContractHash: contractHash, PageSize: pageSize,
		AfterWorkspaceID: afterWorkspaceID, InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey,
		SubjectID: grant.SubjectID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision, CatalogRevision: catalogRevision,
	})
	if err != nil {
		return "", fmt.Errorf("encode Identity Workspace usage cursor: %w", err)
	}
	aead, err := identityWorkspaceUsageCursorAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate Identity Workspace usage cursor nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, payload, []byte(identityWorkspaceUsageCursorAdditionalData))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decodeIdentityWorkspaceUsageCursor(value string, key []byte, grant identitymodel.IdentityWorkspaceUsageGrant, contractVersion, contractHash string, pageSize int) (string, string, error) {
	if value == "" {
		return "", "", nil
	}
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) > 4096 {
		return "", "", identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_cursor_invalid")
	}
	aead, err := identityWorkspaceUsageCursorAEAD(key)
	if err != nil || len(sealed) < aead.NonceSize() {
		return "", "", identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_cursor_invalid")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	payload, err := aead.Open(nil, nonce, ciphertext, []byte(identityWorkspaceUsageCursorAdditionalData))
	if err != nil {
		return "", "", identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_cursor_invalid")
	}
	var cursor identityWorkspaceUsageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.Version != 2 {
		return "", "", identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_cursor_invalid")
	}
	rawAfterWorkspaceID := cursor.AfterWorkspaceID
	cursor.AfterWorkspaceID = strings.TrimSpace(cursor.AfterWorkspaceID)
	cursor.InstallationID = strings.TrimSpace(cursor.InstallationID)
	cursor.ApplicationKey = strings.TrimSpace(cursor.ApplicationKey)
	cursor.SubjectID = strings.TrimSpace(cursor.SubjectID)
	cursor.PermissionKey = strings.TrimSpace(cursor.PermissionKey)
	cursor.AuthorizationRevision = strings.TrimSpace(cursor.AuthorizationRevision)
	cursor.CatalogRevision = strings.TrimSpace(cursor.CatalogRevision)
	if cursor.AfterWorkspaceID == "" || cursor.AfterWorkspaceID != rawAfterWorkspaceID || cursor.CatalogRevision == "" ||
		cursor.ContractVersion != contractVersion || cursor.ContractHash != contractHash || cursor.PageSize != pageSize ||
		cursor.InstallationID != grant.InstallationID || cursor.ApplicationKey != grant.ApplicationKey || cursor.SubjectID != grant.SubjectID ||
		cursor.PermissionKey != grant.PermissionKey || cursor.AuthorizationRevision != grant.AuthorizationRevision {
		return "", "", identityWorkspaceUsageError(apperror.KindForbidden, "backend.identity.workspace_usage_cursor_scope_invalid")
	}
	if _, err := identitymodel.NewWorkspaceID(cursor.AfterWorkspaceID); err != nil {
		return "", "", identityWorkspaceUsageError(apperror.KindBadRequest, "backend.identity.workspace_usage_cursor_invalid")
	}
	return cursor.AfterWorkspaceID, cursor.CatalogRevision, nil
}

func identityWorkspaceUsageCursorAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, identityWorkspaceUsageError(apperror.KindInternal, "backend.identity.workspace_usage_cursor_key_invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity Workspace usage cursor cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity Workspace usage cursor AEAD: %w", err)
	}
	return aead, nil
}

func identityWorkspaceUsageAuditPrincipal(grant identitymodel.IdentityWorkspaceUsageGrant) identitymodel.Principal {
	return identitymodel.Principal{
		Known: true, WorkspaceID: grant.AuditWorkspaceID, UserID: grant.SubjectID,
		SystemScope:           identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, identityWorkspaceUsageSystemPurpose),
		Role:                  identitymodel.RoleSchema{Key: "installation_identity_usage_reader"},
		AuthorizationRevision: grant.AuthorizationRevision,
	}
}

func identityWorkspaceUsageError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
