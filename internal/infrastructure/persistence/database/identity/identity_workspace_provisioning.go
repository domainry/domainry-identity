package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	"github.com/domainry/domainry-orm/query"
)

const (
	workspaceBootstrapOperationOwner          = "identity"
	workspaceBootstrapOperationKind           = "identity.workspace_bootstrap"
	workspaceBootstrapOperationIdempotencyKey = "workspace_bootstrap"
)

type WorkspaceIdentityProvisionStage string

const (
	WorkspaceIdentityProvisionStageUser           WorkspaceIdentityProvisionStage = "user"
	WorkspaceIdentityProvisionStageRole           WorkspaceIdentityProvisionStage = "role"
	WorkspaceIdentityProvisionStageRoleAssignment WorkspaceIdentityProvisionStage = "role_assignment"
	WorkspaceIdentityProvisionStageCompany        WorkspaceIdentityProvisionStage = "company"
	WorkspaceIdentityProvisionStageFirstStore     WorkspaceIdentityProvisionStage = "first_store"
)

// ProvisionWorkspaceIdentityWithExecutor persists only Identity-owned state
// through a host-owned transaction. It deliberately does not commit or roll
// back that transaction.
func (s *SQLIdentityStore) ProvisionWorkspaceIdentityWithExecutor(
	ctx context.Context,
	execer identityUserExecer,
	workspaceID string,
	admin identitymodel.IdentityUser,
	roles []identitymodel.IdentityRole,
	organizations []identitymodel.IdentityOrganizationUnit,
	users []identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
	adminRoleID string,
	after func(WorkspaceIdentityProvisionStage) error,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.writeIdentityUser(ctx, execer, workspaceID, admin); err != nil {
		return fmt.Errorf("provision workspace administrator: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageUser); err != nil {
			return err
		}
	}
	if err := s.roleStore().UpsertBatchWithExecutor(ctx, execer, workspaceID, roles); err != nil {
		return fmt.Errorf("provision workspace roles: %w", err)
	}
	for _, organization := range organizations {
		if err := s.writeIdentityOrganizationUnit(ctx, execer, workspaceID, organization); err != nil {
			return fmt.Errorf("provision acceptance organization %s: %w", organization.ID, err)
		}
	}
	for _, user := range users {
		if err := s.writeIdentityUser(ctx, execer, workspaceID, user); err != nil {
			return fmt.Errorf("provision acceptance user %s: %w", user.ID, err)
		}
	}
	for _, assignment := range assignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, assignment); err != nil {
			return fmt.Errorf("assign acceptance role %s/%s: %w", assignment.UserID, assignment.RoleID, err)
		}
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRole); err != nil {
			return err
		}
	}
	if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, identitymodel.IdentityUserRoleAssignment{
		UserID: admin.ID, RoleID: strings.TrimSpace(adminRoleID), Source: "workspace_provisioning_v1_legacy", Status: "active",
	}); err != nil {
		return fmt.Errorf("assign workspace administrator role: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRoleAssignment); err != nil {
			return err
		}
	}
	return nil
}

// ProvisionWorkspaceAcceptanceFixturesWithExecutor appends only explicitly
// gated verification identities. The trusted company, store, administrator,
// administrator assignment, and administrator credential are never touched.
func (s *SQLIdentityStore) ProvisionWorkspaceAcceptanceFixturesWithExecutor(
	ctx context.Context,
	execer identityUserExecer,
	workspaceID string,
	roles []identitymodel.IdentityRole,
	organizations []identitymodel.IdentityOrganizationUnit,
	users []identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.roleStore().UpsertBatchWithExecutor(ctx, execer, workspaceID, roles); err != nil {
		return fmt.Errorf("provision acceptance roles: %w", err)
	}
	for _, organization := range organizations {
		if err := s.writeIdentityOrganizationUnit(ctx, execer, workspaceID, organization); err != nil {
			return fmt.Errorf("provision acceptance organization %s: %w", organization.ID, err)
		}
	}
	for _, user := range users {
		if err := s.writeIdentityUser(ctx, execer, workspaceID, user); err != nil {
			return fmt.Errorf("provision acceptance user %s: %w", user.ID, err)
		}
	}
	for _, assignment := range assignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, assignment); err != nil {
			return fmt.Errorf("assign acceptance role %s/%s: %w", assignment.UserID, assignment.RoleID, err)
		}
	}
	return nil
}

type WorkspaceIdentityBootstrapGraph struct {
	Company      identitymodel.IdentityOrganizationUnit
	FirstStore   identitymodel.IdentityOrganizationUnit
	InitialAdmin identitymodel.IdentityUser
	Roles        []identitymodel.IdentityRole
	AdminRoleID  string
}

type WorkspaceIdentityBootstrapReceipt struct {
	ID                                   string `json:"id"`
	WorkspaceID                          string `json:"workspace_id"`
	InvocationID                         string `json:"invocation_id"`
	RequestFingerprint                   string `json:"request_fingerprint"`
	ContractVersion                      string `json:"contract_version"`
	ContractHash                         string `json:"contract_hash"`
	CompanyID                            string `json:"company_id"`
	FirstStoreID                         string `json:"first_store_id"`
	InitialAdminUserID                   string `json:"initial_admin_user_id"`
	InitialAdminLoginID                  string `json:"initial_admin_login_id"`
	RoleCatalogSHA256                    string `json:"role_catalog_sha256"`
	InitialWorkspaceAdministratorRoleKey string `json:"initial_workspace_administrator_role_key"`
	CredentialClaimedAt                  string `json:"credential_claimed_at,omitempty"`
	CreatedAt                            string `json:"created_at"`
}

type workspaceIdentityBootstrapReceiptJSON struct {
	ID                                   string `json:"id"`
	WorkspaceID                          string `json:"workspace_id"`
	InvocationID                         string `json:"invocation_id"`
	RequestFingerprint                   string `json:"request_fingerprint"`
	ContractVersion                      string `json:"contract_version"`
	ContractHash                         string `json:"contract_hash"`
	CompanyID                            string `json:"company_id"`
	FirstStoreID                         string `json:"first_store_id"`
	InitialAdminUserID                   string `json:"initial_admin_user_id"`
	InitialAdminLoginID                  string `json:"initial_admin_login_id"`
	RoleCatalogSHA256                    string `json:"role_catalog_sha256"`
	InitialWorkspaceAdministratorRoleKey string `json:"initial_workspace_administrator_role_key"`
	CredentialClaimedAt                  int64  `json:"credential_claimed_at,omitempty"`
	CreatedAt                            int64  `json:"created_at"`
}

func (value WorkspaceIdentityBootstrapReceipt) MarshalJSON() ([]byte, error) {
	return json.Marshal(workspaceIdentityBootstrapReceiptJSON{
		ID: value.ID, WorkspaceID: value.WorkspaceID, InvocationID: value.InvocationID, RequestFingerprint: value.RequestFingerprint,
		ContractVersion: value.ContractVersion, ContractHash: value.ContractHash, CompanyID: value.CompanyID, FirstStoreID: value.FirstStoreID,
		InitialAdminUserID: value.InitialAdminUserID, InitialAdminLoginID: value.InitialAdminLoginID, RoleCatalogSHA256: value.RoleCatalogSHA256,
		InitialWorkspaceAdministratorRoleKey: value.InitialWorkspaceAdministratorRoleKey,
		CredentialClaimedAt:                  timeMillis(value.CredentialClaimedAt), CreatedAt: timeMillis(value.CreatedAt),
	})
}

func (value *WorkspaceIdentityBootstrapReceipt) UnmarshalJSON(raw []byte) error {
	var stored workspaceIdentityBootstrapReceiptJSON
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	*value = WorkspaceIdentityBootstrapReceipt{
		ID: stored.ID, WorkspaceID: stored.WorkspaceID, InvocationID: stored.InvocationID, RequestFingerprint: stored.RequestFingerprint,
		ContractVersion: stored.ContractVersion, ContractHash: stored.ContractHash, CompanyID: stored.CompanyID, FirstStoreID: stored.FirstStoreID,
		InitialAdminUserID: stored.InitialAdminUserID, InitialAdminLoginID: stored.InitialAdminLoginID, RoleCatalogSHA256: stored.RoleCatalogSHA256,
		InitialWorkspaceAdministratorRoleKey: stored.InitialWorkspaceAdministratorRoleKey,
		CredentialClaimedAt:                  timeString(stored.CredentialClaimedAt), CreatedAt: timeString(stored.CreatedAt),
	}
	return nil
}

func WorkspaceIdentityBootstrapReceiptID(workspaceID, invocationID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00workspace_identity_bootstrap_v1\x00" + strings.TrimSpace(invocationID)))
	return "workspace_bootstrap_" + hex.EncodeToString(digest[:16])
}

// WorkspaceIdentityBootstrapStateExistsWithExecutor rejects adoption or
// mutation of a partially initialized Workspace. Every lookup uses the
// host-owned transaction and Workspace scope.
func (s *SQLIdentityStore) WorkspaceIdentityBootstrapStateExistsWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	for _, table := range []string{
		"_identity_organization_units", "_identity_users", "_identity_roles",
		"_identity_user_role_assignments", "_identity_menus", "_identity_role_menu_assignments",
		"_identity_credentials", "_identity_permissions",
	} {
		statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), table, workspaceID).
			Projections(query.Project(query.CountAll())).Build()
		if err != nil {
			return false, fmt.Errorf("build workspace bootstrap state query for %s: %w", table, err)
		}
		var count int
		if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
			return false, fmt.Errorf("query workspace bootstrap state for %s: %w", table, err)
		}
		if count != 0 {
			return true, nil
		}
	}
	return false, nil
}

// WriteWorkspaceIdentityBootstrapGraphWithExecutor writes only the trusted
// Workspace Identity graph. Parentage, the normalized provisioned-role
// directory, and the sole initial role assignment are supplied as already
// validated, purpose-specific values by the module assembly.
func (s *SQLIdentityStore) WriteWorkspaceIdentityBootstrapGraphWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string, graph WorkspaceIdentityBootstrapGraph, after func(WorkspaceIdentityProvisionStage) error) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.writeIdentityOrganizationUnit(ctx, execer, workspaceID, graph.Company); err != nil {
		return fmt.Errorf("provision workspace company: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageCompany); err != nil {
			return err
		}
	}
	if err := s.writeIdentityOrganizationUnit(ctx, execer, workspaceID, graph.FirstStore); err != nil {
		return fmt.Errorf("provision workspace first store: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageFirstStore); err != nil {
			return err
		}
	}
	if err := s.writeIdentityUser(ctx, execer, workspaceID, graph.InitialAdmin); err != nil {
		return fmt.Errorf("provision workspace initial administrator: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageUser); err != nil {
			return err
		}
	}
	if err := s.roleStore().UpsertBatchWithExecutor(ctx, execer, workspaceID, graph.Roles); err != nil {
		return fmt.Errorf("provision workspace bootstrap roles: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRole); err != nil {
			return err
		}
	}
	if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, identitymodel.IdentityUserRoleAssignment{
		UserID: graph.InitialAdmin.ID, RoleID: strings.TrimSpace(graph.AdminRoleID), Source: "workspace_bootstrap_v1", Status: "active",
	}); err != nil {
		return fmt.Errorf("assign workspace initial administrator role: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRoleAssignment); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLIdentityStore) GetWorkspaceIdentityBootstrapReceiptWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID, invocationID string) (WorkspaceIdentityBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	if !s.OperationsPersistenceBound() {
		return WorkspaceIdentityBootstrapReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadReferenced(ctx, execer, s.sqlRenderer(), workspaceID, workspaceBootstrapOperationOwner, workspaceBootstrapOperationKind, workspaceBootstrapOperationIdempotencyKey)
	if err != nil || !found {
		return WorkspaceIdentityBootstrapReceipt{}, found, err
	}
	if operation.Reference != strings.TrimSpace(invocationID) {
		return WorkspaceIdentityBootstrapReceipt{}, false, nil
	}
	return decodeWorkspaceIdentityBootstrapReceipt(operation, workspaceID)
}

func (s *SQLIdentityStore) WorkspaceIdentityBootstrapReceiptExistsWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	if !s.OperationsPersistenceBound() {
		return false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	_, found, err := operationreceipt.Load(ctx, execer, s.sqlRenderer(), workspaceID, workspaceBootstrapOperationOwner, workspaceBootstrapOperationKind, workspaceBootstrapOperationIdempotencyKey)
	return found, err
}

func (s *SQLIdentityStore) InsertWorkspaceIdentityBootstrapReceiptWithExecutor(ctx context.Context, execer identityUserExecer, receipt WorkspaceIdentityBootstrapReceipt) error {
	var err error
	receipt.WorkspaceID, err = identityWorkspaceID(receipt.WorkspaceID)
	if err != nil {
		return err
	}
	if !s.OperationsPersistenceBound() {
		return fmt.Errorf("identity shared Operations persistence is not bound")
	}
	if receipt.CreatedAt == "" {
		receipt.CreatedAt = nowString()
	}
	resultJSON, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode workspace bootstrap receipt: %w", err)
	}
	metadataJSON, _ := json.Marshal(map[string]string{
		"contract_version": receipt.ContractVersion,
		"contract_hash":    receipt.ContractHash,
		"role_catalog":     receipt.RoleCatalogSHA256,
	})
	relatedIDsJSON, _ := json.Marshal([]string{receipt.WorkspaceID, receipt.CompanyID, receipt.FirstStoreID, receipt.InitialAdminUserID})
	if err := operationreceipt.InsertSucceeded(ctx, execer, s.sqlRenderer(), operationreceipt.Succeeded{
		ID: receipt.ID, WorkspaceID: receipt.WorkspaceID, Owner: workspaceBootstrapOperationOwner, Kind: workspaceBootstrapOperationKind,
		ActionKey: "identity.workspace.bootstrap", ResourceType: "workspace", ResourceID: receipt.WorkspaceID,
		IdempotencyKey: workspaceBootstrapOperationIdempotencyKey, RequestFingerprint: receipt.RequestFingerprint,
		RequestedBy: "identity.workspace_bootstrap", Reason: "bootstrap workspace identity graph", Reference: receipt.InvocationID,
		ResultJSON: resultJSON, MetadataJSON: metadataJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: receipt.CreatedAt,
	}); err != nil {
		return fmt.Errorf("insert workspace bootstrap receipt: %w", err)
	}
	return nil
}

func (s *SQLIdentityStore) GetCommittedWorkspaceIdentityBootstrapReceipt(ctx context.Context, workspaceID, receiptID string) (WorkspaceIdentityBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	if !s.OperationsPersistenceBound() {
		return WorkspaceIdentityBootstrapReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadByID(ctx, s.DB(), s.sqlRenderer(), workspaceID, workspaceBootstrapOperationOwner, workspaceBootstrapOperationKind, receiptID)
	if err != nil || !found {
		return WorkspaceIdentityBootstrapReceipt{}, found, err
	}
	return decodeWorkspaceIdentityBootstrapReceipt(operation, workspaceID)
}

func (s *SQLIdentityStore) MarkWorkspaceIdentityBootstrapCredentialClaimed(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	if !s.OperationsPersistenceBound() {
		return false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadByID(ctx, s.DB(), s.sqlRenderer(), workspaceID, workspaceBootstrapOperationOwner, workspaceBootstrapOperationKind, receiptID)
	if err != nil || !found {
		return false, err
	}
	receipt, found, err := decodeWorkspaceIdentityBootstrapReceipt(operation, workspaceID)
	if err != nil || !found || receipt.CredentialClaimedAt != "" {
		return false, err
	}
	receipt.CredentialClaimedAt = nowString()
	next, err := json.Marshal(receipt)
	if err != nil {
		return false, err
	}
	return operationreceipt.UpdateSucceededResult(ctx, s.DB(), s.sqlRenderer(), workspaceID, workspaceBootstrapOperationOwner, workspaceBootstrapOperationKind, receiptID, operation.ResultJSON, next, receipt.CredentialClaimedAt)
}

func decodeWorkspaceIdentityBootstrapReceipt(operation operationreceipt.Receipt, workspaceID string) (WorkspaceIdentityBootstrapReceipt, bool, error) {
	var receipt WorkspaceIdentityBootstrapReceipt
	if err := json.Unmarshal(operation.ResultJSON, &receipt); err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, fmt.Errorf("decode workspace bootstrap operation: %w", err)
	}
	if receipt.ID != operation.ID || receipt.WorkspaceID != workspaceID || receipt.WorkspaceID != operation.ResourceID ||
		receipt.InvocationID != operation.Reference || receipt.RequestFingerprint != operation.RequestFingerprint || receipt.CreatedAt != operation.CreatedAt {
		return WorkspaceIdentityBootstrapReceipt{}, false, fmt.Errorf("identity shared workspace bootstrap operation scope mismatch")
	}
	return receipt, true, nil
}
