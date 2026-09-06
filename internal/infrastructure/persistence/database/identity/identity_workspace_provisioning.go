package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
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
	ID                                   string
	WorkspaceID                          string
	InvocationID                         string
	RequestFingerprint                   string
	ContractVersion                      string
	ContractHash                         string
	CompanyID                            string
	FirstStoreID                         string
	InitialAdminUserID                   string
	InitialAdminLoginID                  string
	RoleCatalogSHA256                    string
	InitialWorkspaceAdministratorRoleKey string
	CredentialClaimedAt                  string
	CreatedAt                            string
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
		"_identity_user_role_assignments", "_identity_credentials", "_identity_permissions",
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
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_workspace_bootstrap_receipts", workspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "company_id", "first_store_id", "initial_admin_user_id", "initial_admin_login_id", "role_catalog_sha256", "initial_workspace_administrator_role_key", "credential_claimed_at", "created_at").
		Where(query.Equal("invocation_id", strings.TrimSpace(invocationID))).Limit(1).Build()
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, fmt.Errorf("build workspace bootstrap receipt query: %w", err)
	}
	receipt, err := scanWorkspaceIdentityBootstrapReceipt(execer.QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkspaceIdentityBootstrapReceipt{}, false, nil
	}
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	return receipt, true, nil
}

func (s *SQLIdentityStore) WorkspaceIdentityBootstrapReceiptExistsWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_workspace_bootstrap_receipts", workspaceID).
		Projections(query.Project(query.CountAll())).Build()
	if err != nil {
		return false, err
	}
	var count int
	if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}

func (s *SQLIdentityStore) InsertWorkspaceIdentityBootstrapReceiptWithExecutor(ctx context.Context, execer identityUserExecer, receipt WorkspaceIdentityBootstrapReceipt) error {
	var err error
	receipt.WorkspaceID, err = identityWorkspaceID(receipt.WorkspaceID)
	if err != nil {
		return err
	}
	if receipt.CreatedAt == "" {
		receipt.CreatedAt = nowString()
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_workspace_bootstrap_receipts", receipt.WorkspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "company_id", "first_store_id", "initial_admin_user_id", "initial_admin_login_id", "role_catalog_sha256", "initial_workspace_administrator_role_key", "created_at").
		Values(receipt.ID, receipt.InvocationID, receipt.RequestFingerprint, receipt.ContractVersion, receipt.ContractHash, receipt.CompanyID, receipt.FirstStoreID, receipt.InitialAdminUserID, receipt.InitialAdminLoginID, receipt.RoleCatalogSHA256, receipt.InitialWorkspaceAdministratorRoleKey, receipt.CreatedAt).Build()
	if err != nil {
		return fmt.Errorf("build workspace bootstrap receipt insert: %w", err)
	}
	if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("insert workspace bootstrap receipt: %w", err)
	}
	return nil
}

func (s *SQLIdentityStore) GetCommittedWorkspaceIdentityBootstrapReceipt(ctx context.Context, workspaceID, receiptID string) (WorkspaceIdentityBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_workspace_bootstrap_receipts", workspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "company_id", "first_store_id", "initial_admin_user_id", "initial_admin_login_id", "role_catalog_sha256", "initial_workspace_administrator_role_key", "credential_claimed_at", "created_at").
		Where(query.Equal("id", strings.TrimSpace(receiptID))).Limit(1).Build()
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	receipt, err := scanWorkspaceIdentityBootstrapReceipt(s.DB().QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkspaceIdentityBootstrapReceipt{}, false, nil
	}
	if err != nil {
		return WorkspaceIdentityBootstrapReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	return receipt, true, nil
}

func (s *SQLIdentityStore) MarkWorkspaceIdentityBootstrapCredentialClaimed(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_workspace_bootstrap_receipts", workspaceID).
		Set("credential_claimed_at", nowString()).
		Where(query.And(query.Equal("id", strings.TrimSpace(receiptID)), query.IsNull("credential_claimed_at"))).Build()
	if err != nil {
		return false, fmt.Errorf("build workspace bootstrap credential claim: %w", err)
	}
	result, err := s.DB().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func scanWorkspaceIdentityBootstrapReceipt(row *sql.Row) (WorkspaceIdentityBootstrapReceipt, error) {
	var receipt WorkspaceIdentityBootstrapReceipt
	var claimed sql.NullString
	err := row.Scan(&receipt.ID, &receipt.InvocationID, &receipt.RequestFingerprint, &receipt.ContractVersion, &receipt.ContractHash, &receipt.CompanyID, &receipt.FirstStoreID, &receipt.InitialAdminUserID, &receipt.InitialAdminLoginID, &receipt.RoleCatalogSHA256, &receipt.InitialWorkspaceAdministratorRoleKey, &claimed, &receipt.CreatedAt)
	if claimed.Valid {
		receipt.CredentialClaimedAt = claimed.String
	}
	return receipt, err
}
